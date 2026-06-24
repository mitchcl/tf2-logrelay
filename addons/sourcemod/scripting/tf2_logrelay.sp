/**
 * tf2_logrelay — PII-stripped, HMAC-authenticated UDP relay of a Source/TF2 server's game log.
 * Packet: <64-hex HMAC-SHA256><serverid>\x1f<hostname>\x1f<logline>, HMAC over the payload.
 * Requires the Socket and cURL extensions. MIT licensed.
 */

#include <sourcemod>
#include "logrelay_socket.inc"
#include "logrelay_curl.inc"

#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION   "2.0.0"
#define MAX_LINE         1024
#define MAX_PAYLOAD      (256 + MAX_LINE)
#define HMAC_BLOCK       64
#define HMAC_HEXLEN      64
#define SEP              0x1F
#define MAX_RECIPIENTS   16

public Plugin myinfo =
{
    name        = "TF2 Log Relay (UDP/HMAC)",
    author      = "mitchcl",
    description = "Forwards scrubbed gameplay log lines over HMAC-authenticated UDP",
    version     = PLUGIN_VERSION,
    url         = "https://github.com/mitchcl/tf2-logrelay"
};

ConVar g_cvEnabled;
ConVar g_cvHost;
ConVar g_cvPort;
ConVar g_cvKey;
ConVar g_cvServerId;
ConVar g_cvStrict;
ConVar g_cvSendChat;
ConVar g_cvDebug;
ConVar g_cvHostport;
ConVar g_cvHostip;
ConVar g_cvHostname;

Handle g_hSocket = null;

enum struct Recipient
{
    char host[256];
    int  port;
    char key[129];
}
Recipient g_Recipients[MAX_RECIPIENTS];
int g_RecipientCount = 0;

// Only forwarded when logrelay_strict is 1.
static const char g_Whitelist[][] =
{
    "triggered \"damage\"",
    "triggered \"shot_hit\"",
    "triggered \"shot_fired\"",
    "\" killed \"",
    "triggered \"healed\"",
    "triggered \"chargedeployed\"",
    "triggered \"medic_death\"",
    "triggered \"lost_uber_advantage\"",
    "triggered \"domination\"",
    "triggered \"kill assist\"",
    "triggered \"captureblocked\"",
    "triggered \"pointcaptured\"",
    "committed suicide with",
    "spawned as \"",
    "changed role to \"",
    "World triggered \"Round_Start\"",
    "World triggered \"Mini_Round_Start\"",
    "World triggered \"Round_Win\"",
    "World triggered \"Round_Length\"",
    "World triggered \"Round_Overtime\"",
    "World triggered \"Game_Over\"",
    "Loading map \"",
};

public void OnPluginStart()
{
    CreateConVar("logrelay_version", PLUGIN_VERSION, "tf2-logrelay version", FCVAR_NOTIFY | FCVAR_DONTRECORD);
    g_cvEnabled  = CreateConVar("logrelay_enabled", "1", "Enable forwarding.", _, true, 0.0, true, 1.0);
    g_cvHost     = CreateConVar("logrelay_host", "", "UDP host/IP to send to (empty = inert).");
    g_cvPort     = CreateConVar("logrelay_port", "0", "UDP port to send to.", _, true, 0.0, true, 65535.0);
    g_cvKey      = CreateConVar("logrelay_key", "", "Shared secret used as the HMAC-SHA256 key.", FCVAR_PROTECTED);
    g_cvServerId = CreateConVar("logrelay_server_id", "", "Server id in each packet. Falls back to the game ip:port.");
    g_cvStrict   = CreateConVar("logrelay_strict", "0", "1 = whitelist only; 0 = everything except PII/chat.", _, true, 0.0, true, 1.0);
    g_cvSendChat = CreateConVar("logrelay_send_chat", "0", "1 = also forward chat.", _, true, 0.0, true, 1.0);
    g_cvDebug    = CreateConVar("logrelay_debug", "0", "Log failures to the server console.", _, true, 0.0, true, 1.0);

    g_cvHostport = FindConVar("hostport");
    g_cvHostip   = FindConVar("hostip");
    g_cvHostname = FindConVar("hostname");

    g_hSocket = SocketCreate(SOCKET_UDP, OnSocketError);

    AddGameLogHook(OnGameLog);

    RegServerCmd("logrelay_add", Cmd_Add, "logrelay_add <host> <port> <key> - add/update a recipient");
    RegServerCmd("logrelay_remove", Cmd_Remove, "logrelay_remove <host> <port> - remove a recipient");
    RegServerCmd("logrelay_list", Cmd_List, "logrelay_list - list recipients");
    RegServerCmd("logrelay_clear", Cmd_Clear, "logrelay_clear - remove all config recipients");
    RegServerCmd("logrelay_reload", Cmd_Reload, "logrelay_reload - reload recipients from cvars + config");

    AutoExecConfig(true, "tf2_logrelay");
    CreateTimer(3.0, Timer_Startup);
}

public Action Cmd_Add(int args)
{
    char addr[280], key[129];
    GetCmdArg(1, addr, sizeof addr);
    GetCmdArg(2, key, sizeof key);
    char host[256];
    int port;
    if (args < 2 || !SplitAddr(addr, host, sizeof host, port) || key[0] == '\0')
    {
        PrintToServer("[logrelay] usage: logrelay_add <ip:port> <key>");
        return Plugin_Handled;
    }
    PersistRecipient(host, port, key);
    LoadRecipients();
    PrintToServer("[logrelay] added %s:%d (%d recipient(s))", host, port, g_RecipientCount);
    return Plugin_Handled;
}

public Action Cmd_Remove(int args)
{
    char addr[280];
    GetCmdArg(1, addr, sizeof addr);
    char host[256];
    int port;
    if (args < 1 || !SplitAddr(addr, host, sizeof host, port))
    {
        PrintToServer("[logrelay] usage: logrelay_remove <ip:port>");
        return Plugin_Handled;
    }
    bool found = RemovePersistedRecipient(host, port);
    LoadRecipients();
    PrintToServer("[logrelay] %s %s:%d (%d recipient(s))", found ? "removed" : "not found", host, port, g_RecipientCount);
    return Plugin_Handled;
}

bool SplitAddr(const char[] addr, char[] host, int hostlen, int &port)
{
    int c = FindCharInString(addr, ':', true);
    if (c <= 0)
        return false;
    strcopy(host, hostlen, addr);
    host[c] = '\0';
    port = StringToInt(addr[c + 1]);
    return host[0] != '\0' && port > 0 && port <= 65535;
}

public Action Cmd_List(int args)
{
    PrintToServer("[logrelay] %d recipient(s):", g_RecipientCount);
    for (int r = 0; r < g_RecipientCount; r++)
        PrintToServer("  %s:%d", g_Recipients[r].host, g_Recipients[r].port);
    return Plugin_Handled;
}

public Action Cmd_Clear(int args)
{
    ClearPersistedRecipients();
    LoadRecipients();
    PrintToServer("[logrelay] cleared config recipients (%d recipient(s))", g_RecipientCount);
    return Plugin_Handled;
}

public Action Cmd_Reload(int args)
{
    LoadRecipients();
    PrintToServer("[logrelay] reloaded (%d recipient(s))", g_RecipientCount);
    return Plugin_Handled;
}

// Announce the map once after the cfg has applied, so a source appears on an idle server too.
public Action Timer_Startup(Handle timer)
{
    LoadRecipients();
    LogMessage("[logrelay] %d recipient(s) configured", g_RecipientCount);
    AnnounceMap();
    return Plugin_Stop;
}

public void OnConfigsExecuted()
{
    LoadRecipients();
    AnnounceMap();
}

public void OnMapStart()
{
    AnnounceMap();
}

public void OnPluginEnd()
{
    RemoveGameLogHook(OnGameLog);
    if (g_hSocket != null)
    {
        CloseHandle(g_hSocket);
        g_hSocket = null;
    }
}

public void OnSocketError(Handle socket, const int errorType, const int errorNum, any data)
{
    LogError("[logrelay] socket error type=%d num=%d", errorType, errorNum);
}

bool HaveTarget()
{
    return g_cvEnabled.BoolValue && g_hSocket != null && g_RecipientCount > 0;
}

// Recipients come from the single cvars (logrelay_host/port/key) plus, for multiple destinations
// (e.g. a casting org + tf2esports), configs/tf2_logrelay_recipients.cfg — each with its own key.
void LoadRecipients()
{
    g_RecipientCount = 0;

    char host[256], key[129];
    g_cvHost.GetString(host, sizeof host);
    g_cvKey.GetString(key, sizeof key);
    if (host[0] != '\0' && g_cvPort.IntValue > 0 && key[0] != '\0')
        AddRecipient(host, g_cvPort.IntValue, key);

    char path[PLATFORM_MAX_PATH];
    BuildPath(Path_SM, path, sizeof path, "configs/tf2_logrelay_recipients.cfg");
    if (!FileExists(path))
        return;

    KeyValues kv = new KeyValues("Recipients");
    if (kv.ImportFromFile(path) && kv.GotoFirstSubKey())
    {
        do
        {
            char h[256], k[129];
            kv.GetString("host", h, sizeof h);
            kv.GetString("key", k, sizeof k);
            int p = kv.GetNum("port");
            if (h[0] != '\0' && p > 0 && k[0] != '\0')
                AddRecipient(h, p, k);
        }
        while (kv.GotoNextKey());
    }
    delete kv;
}

void AddRecipient(const char[] host, int port, const char[] key)
{
    if (g_RecipientCount >= MAX_RECIPIENTS)
        return;
    for (int i = 0; i < g_RecipientCount; i++)
        if (g_Recipients[i].port == port && StrEqual(g_Recipients[i].host, host))
            return;
    strcopy(g_Recipients[g_RecipientCount].host, 256, host);
    g_Recipients[g_RecipientCount].port = port;
    strcopy(g_Recipients[g_RecipientCount].key, 129, key);
    g_RecipientCount++;
}

void RecipientsPath(char[] path, int maxlen)
{
    BuildPath(Path_SM, path, maxlen, "configs/tf2_logrelay_recipients.cfg");
}

void PersistRecipient(const char[] host, int port, const char[] key)
{
    char path[PLATFORM_MAX_PATH];
    RecipientsPath(path, sizeof path);
    KeyValues kv = new KeyValues("Recipients");
    kv.ImportFromFile(path);
    char section[320];
    Format(section, sizeof section, "%s:%d", host, port);
    kv.JumpToKey(section, true);
    kv.SetString("host", host);
    kv.SetNum("port", port);
    kv.SetString("key", key);
    kv.Rewind();
    kv.ExportToFile(path);
    delete kv;
}

bool RemovePersistedRecipient(const char[] host, int port)
{
    char path[PLATFORM_MAX_PATH];
    RecipientsPath(path, sizeof path);
    KeyValues kv = new KeyValues("Recipients");
    bool found = false;
    if (kv.ImportFromFile(path))
    {
        char section[320];
        Format(section, sizeof section, "%s:%d", host, port);
        if (kv.JumpToKey(section))
        {
            kv.DeleteThis();
            found = true;
        }
        kv.Rewind();
        kv.ExportToFile(path);
    }
    delete kv;
    return found;
}

void ClearPersistedRecipients()
{
    char path[PLATFORM_MAX_PATH];
    RecipientsPath(path, sizeof path);
    KeyValues kv = new KeyValues("Recipients");
    kv.ExportToFile(path);
    delete kv;
}

public Action OnGameLog(const char[] message)
{
    if (!HaveTarget())
        return Plugin_Continue;

    if (ContainsIPv4(message))   // never forward a line carrying an IP
        return Plugin_Continue;

    if (!g_cvSendChat.BoolValue &&
        (StrContains(message, "\" say \"") != -1 || StrContains(message, "\" say_team \"") != -1))
        return Plugin_Continue;

    if (g_cvStrict.BoolValue && !IsWhitelisted(message))
        return Plugin_Continue;

    SendLine(message);
    return Plugin_Continue;
}

void AnnounceMap()
{
    if (!HaveTarget())
        return;
    char map[PLATFORM_MAX_PATH];
    GetCurrentMap(map, sizeof map);
    if (map[0] == '\0')
        return;
    char line[MAX_LINE];
    Format(line, sizeof line, "Loading map \"%s\"", map);
    SendLine(line);
}

void BuildServerId(char[] buf, int maxlen)
{
    int port = (g_cvHostport != null && g_cvHostport.IntValue > 0) ? g_cvHostport.IntValue : 27015;
    int ip = (g_cvHostip != null) ? g_cvHostip.IntValue : 0;
    if (ip != 0)
        Format(buf, maxlen, "%d.%d.%d.%d:%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, port);
    else
        IntToString(port, buf, maxlen);
}

void SendLine(const char[] message)
{
    char line[MAX_LINE];
    if (strncmp(message, "L ", 2) == 0)
    {
        strcopy(line, sizeof line, message);
    }
    else
    {
        char ts[32];
        FormatTime(ts, sizeof ts, "%m/%d/%Y - %H:%M:%S");
        Format(line, sizeof line, "L %s: %s", ts, message);
    }
    StripNewline(line);

    char sid[128];
    g_cvServerId.GetString(sid, sizeof sid);
    if (sid[0] == '\0')
        BuildServerId(sid, sizeof sid);

    char sv[128];
    if (g_cvHostname != null)
        g_cvHostname.GetString(sv, sizeof sv);
    ReplaceString(sv, sizeof sv, "\x1f", " ");

    char payload[MAX_PAYLOAD];
    int plen = strcopy(payload, sizeof payload, sid);
    payload[plen++] = SEP;
    plen += strcopy(payload[plen], sizeof payload - plen, sv);
    payload[plen++] = SEP;
    plen += strcopy(payload[plen], sizeof payload - plen, line);

    // One packet per recipient — same payload, HMAC'd with each recipient's own key.
    for (int r = 0; r < g_RecipientCount; r++)
    {
        char mac[HMAC_HEXLEN + 1];
        if (!HmacSha256Hex(g_Recipients[r].key, strlen(g_Recipients[r].key), payload, plen, mac, sizeof mac))
        {
            if (g_cvDebug.BoolValue)
                LogError("[logrelay] HMAC failed for recipient %d", r);
            continue;
        }

        char packet[HMAC_HEXLEN + MAX_PAYLOAD];
        int pktlen = strcopy(packet, sizeof packet, mac);
        for (int i = 0; i < plen; i++)
            packet[pktlen++] = payload[i];

        SocketSendTo(g_hSocket, packet, pktlen, g_Recipients[r].host, g_Recipients[r].port);
    }
}

// HMAC(K,m) = H((K0 ^ opad) || H((K0 ^ ipad) || m)) via the native OpenSSL SHA-256.
bool HmacSha256Hex(const char[] key, int keyLen, const char[] msg, int msgLen, char[] out, int outLen)
{
    int k0[HMAC_BLOCK];
    if (keyLen > HMAC_BLOCK)
    {
        char keyHex[HMAC_HEXLEN + 1];
        if (!curl_hash_string(key, keyLen, Openssl_Hash_SHA256, keyHex, sizeof keyHex))
            return false;
        int dig[32];
        HexToBytes(keyHex, dig, 32);
        for (int i = 0; i < 32; i++) k0[i] = dig[i];
        for (int i = 32; i < HMAC_BLOCK; i++) k0[i] = 0;
    }
    else
    {
        for (int i = 0; i < keyLen; i++) k0[i] = key[i] & 0xFF;
        for (int i = keyLen; i < HMAC_BLOCK; i++) k0[i] = 0;
    }

    char inner[HMAC_BLOCK + MAX_PAYLOAD];
    int ip = 0;
    for (int i = 0; i < HMAC_BLOCK; i++) inner[ip++] = (k0[i] ^ 0x36) & 0xFF;
    for (int i = 0; i < msgLen; i++) inner[ip++] = msg[i] & 0xFF;

    char innerHex[HMAC_HEXLEN + 1];
    if (!curl_hash_string(inner, ip, Openssl_Hash_SHA256, innerHex, sizeof innerHex))
        return false;
    int innerDig[32];
    HexToBytes(innerHex, innerDig, 32);

    char outer[HMAC_BLOCK + 32];
    int op = 0;
    for (int i = 0; i < HMAC_BLOCK; i++) outer[op++] = (k0[i] ^ 0x5c) & 0xFF;
    for (int i = 0; i < 32; i++) outer[op++] = innerDig[i] & 0xFF;

    return curl_hash_string(outer, op, Openssl_Hash_SHA256, out, outLen);
}

void HexToBytes(const char[] hex, int[] out, int nbytes)
{
    for (int i = 0; i < nbytes; i++)
        out[i] = (HexVal(hex[i * 2]) << 4) | HexVal(hex[i * 2 + 1]);
}

int HexVal(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

bool ContainsIPv4(const char[] s)
{
    int len = strlen(s);
    for (int i = 0; i < len; i++)
    {
        if (!IsCharNumeric(s[i]))
            continue;
        if (i > 0 && (IsCharNumeric(s[i - 1]) || s[i - 1] == '.'))
            continue;

        int p = i;
        bool ok = true;
        for (int g = 0; g < 4; g++)
        {
            int d = 0;
            while (p < len && IsCharNumeric(s[p])) { d++; p++; }
            if (d < 1 || d > 3) { ok = false; break; }
            if (g < 3)
            {
                if (p < len && s[p] == '.') p++;
                else { ok = false; break; }
            }
        }
        if (ok)
            return true;
    }
    return false;
}

bool IsWhitelisted(const char[] message)
{
    for (int i = 0; i < sizeof(g_Whitelist); i++)
    {
        if (StrContains(message, g_Whitelist[i]) != -1)
            return true;
    }
    return false;
}

void StripNewline(char[] s)
{
    int l = strlen(s);
    while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r'))
        s[--l] = '\0';
}
