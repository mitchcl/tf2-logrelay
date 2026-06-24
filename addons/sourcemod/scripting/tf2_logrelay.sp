/**
 * tf2_logrelay.sp  —  privacy-respecting game-log relay for Source/TF2 servers
 *
 * WHAT IT DOES
 *   Watches the server's own game log and forwards gameplay log lines to a configured HTTPS
 *   endpoint, batched every few seconds. The forwarded lines are the standard "HL Log Standard"
 *   format — the same data logs.tf ingests at the end of a match. It's a privacy-respecting,
 *   opt-in alternative to raw `logaddress_add`: the operator installs it and points it at their
 *   own endpoint. By default it runs in COMPREHENSIVE mode: every log line is forwarded EXCEPT
 *   the ones carrying PII or chat (see below). Set `logrelay_strict 1` to forward only an
 *   explicit gameplay whitelist instead.
 *
 * WHAT IT NEVER SENDS  (privacy is by construction, not by trust)
 *   - Player IP addresses. The ONLY log lines that contain an IP are connection / rcon lines
 *     ("... connected, address 1.2.3.4", "rcon from 1.2.3.4"). EVERY line is scanned for a
 *     dotted-quad IPv4 and dropped if one is present — a universal guard that needs no
 *     per-line-type knowledge, so an IP can never leave the server.
 *   - Chat. "say" / "say_team" lines are dropped (private communication) unless the operator
 *     explicitly opts in with `logrelay_send_chat 1`.
 *   Identity in the forwarded lines is SteamID + in-game name only — public scoreboard data.
 *   (The server's OWN public ip:port is reported in a header for stream identification; that's
 *   the public game address, not player PII.)
 *
 * WHY A PLUGIN (vs. logaddress_add)
 *   logaddress streams EVERY raw line, including the IP-bearing connection lines, to the
 *   receiver. This plugin filters at the source: nothing the operator hasn't consented to,
 *   and no PII, ever leaves the machine. Returns Plugin_Continue everywhere — it observes the
 *   log, it never suppresses or alters it, so logs.tf / SourceTV / normal logging are
 *   completely unaffected.
 *
 * REQUIREMENTS
 *   - SourceMod 1.11+ (modern syntax)
 *   - SteamWorks extension (present on virtually all competitive servers)
 *   - For full damage/accuracy/medic stats: the standard logs.tf plugins (SupStats2 + the
 *     medic-stats plugin). Without them you still get kills, caps and round/match events.
 *
 * MIT licensed. Point logrelay_url at any compatible receiver (see README for the wire format).
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <SteamWorks>

#define PLUGIN_VERSION   "1.0.0"
#define MAX_LINE         1024
#define MAX_BUFFER_LINES 4000     // hard cap so an unreachable endpoint can't grow memory

public Plugin myinfo =
{
    name        = "TF2 Log Relay",
    author      = "mitchcl",
    description = "Forwards scrubbed gameplay log lines (no IPs, no chat) to a configurable HTTPS endpoint",
    version     = PLUGIN_VERSION,
    url         = "https://github.com/mitchcl/tf2-logrelay"
};

ConVar g_cvEnabled;
ConVar g_cvUrl;
ConVar g_cvKey;
ConVar g_cvServerId;
ConVar g_cvInterval;
ConVar g_cvDebug;
ConVar g_cvStrict;
ConVar g_cvSendChat;
ConVar g_cvHostname;

ArrayList g_hBuffer;
Handle    g_hFlushTimer = null;
bool      g_bHaveUrl    = false;
bool      g_bWarnedFull = false;
bool      g_bMapAnnounced = false;   // have we emitted a "Loading map" line since (re)load?

char g_sBody[262144];             // one flush body (256 KB); leftover lines roll to next flush

// Gameplay-line whitelist — used ONLY when logrelay_strict is 1. Most frequent verbs first so
// the common case short-circuits fast.
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
    CreateConVar("logrelay_version", PLUGIN_VERSION, "tf2-logrelay plugin version",
        FCVAR_NOTIFY | FCVAR_DONTRECORD);

    g_cvEnabled  = CreateConVar("logrelay_enabled", "1", "Enable forwarding of gameplay stats.", _, true, 0.0, true, 1.0);
    g_cvUrl      = CreateConVar("logrelay_url", "", "HTTPS endpoint to POST batched gameplay lines to (empty = inert).");
    g_cvKey      = CreateConVar("logrelay_key", "", "API key sent as the X-Api-Key header.", FCVAR_PROTECTED);
    g_cvServerId = CreateConVar("logrelay_server_id", "", "Stable server identifier (X-Server-Id). Falls back to the hostname.");
    g_cvInterval = CreateConVar("logrelay_flush_interval", "2.0", "Seconds between batched uploads.", _, true, 0.5, true, 30.0);
    g_cvDebug    = CreateConVar("logrelay_debug", "0", "Log upload failures to the server console.", _, true, 0.0, true, 1.0);
    g_cvStrict   = CreateConVar("logrelay_strict", "0", "1 = forward ONLY the explicit gameplay whitelist; 0 = forward everything except PII/chat.", _, true, 0.0, true, 1.0);
    g_cvSendChat = CreateConVar("logrelay_send_chat", "0", "1 = also forward say/say_team chat lines. Off by default (private communication).", _, true, 0.0, true, 1.0);

    g_cvHostname = FindConVar("hostname");

    g_hBuffer = new ArrayList(ByteCountToCells(MAX_LINE));

    g_cvUrl.AddChangeHook(OnUrlChanged);
    g_cvInterval.AddChangeHook(OnIntervalChanged);

    // Observe the game log. We never return Plugin_Handled, so the normal log is untouched.
    AddGameLogHook(OnGameLog);

    AutoExecConfig(true, "tf2_logrelay");
}

public void OnConfigsExecuted()
{
    RefreshHaveUrl();
    StartFlushTimer();
}

public void OnPluginEnd()
{
    RemoveGameLogHook(OnGameLog);
    if (g_hFlushTimer != null)
    {
        KillTimer(g_hFlushTimer);
        g_hFlushTimer = null;
    }
    delete g_hBuffer;
}

public void OnMapStart()
{
    // Announce the new map (the receiver resets per-map score on it). Also covers builds where
    // the engine's own "Loading map" line doesn't reach the game-log hook.
    BufferCurrentMap();
}

void OnUrlChanged(ConVar cv, const char[] oldValue, const char[] newValue)
{
    RefreshHaveUrl();
}

void OnIntervalChanged(ConVar cv, const char[] oldValue, const char[] newValue)
{
    StartFlushTimer();
}

void RefreshHaveUrl()
{
    char url[512];
    g_cvUrl.GetString(url, sizeof url);
    g_bHaveUrl = (url[0] != '\0');
    // TLS is driven by the URL scheme (SteamWorks does the handshake when it's https://). Warn
    // loudly if the operator points us at a plaintext endpoint — gameplay data shouldn't ride http.
    if (g_bHaveUrl && strncmp(url, "https://", 8, false) != 0)
        LogError("[logrelay] logrelay_url is not https:// — data would be sent unencrypted. Use an https endpoint.");
}

void StartFlushTimer()
{
    if (g_hFlushTimer != null)
    {
        KillTimer(g_hFlushTimer);
        g_hFlushTimer = null;
    }
    g_hFlushTimer = CreateTimer(g_cvInterval.FloatValue, Timer_Flush, _, TIMER_REPEAT);
}

public Action OnGameLog(const char[] message)
{
    if (!g_bHaveUrl || !g_cvEnabled.BoolValue)
        return Plugin_Continue;

    // Universal PII guard: never forward a line containing an IPv4 address (connection / rcon
    // lines are the only ones that do). This is intentionally type-agnostic so it also catches
    // any future log line that happens to embed an IP.
    if (ContainsIPv4(message))
        return Plugin_Continue;

    // Chat is private communication — dropped unless the operator opts in.
    if (!g_cvSendChat.BoolValue &&
        (StrContains(message, "\" say \"") != -1 || StrContains(message, "\" say_team \"") != -1))
        return Plugin_Continue;

    // Strict mode forwards only the explicit gameplay whitelist; comprehensive mode (default)
    // forwards everything that survived the PII/chat guards above.
    if (g_cvStrict.BoolValue && !IsWhitelisted(message))
        return Plugin_Continue;

    BufferLine(message);
    return Plugin_Continue;
}

// True if `s` contains a dotted-quad IPv4 (four groups of 1-3 digits separated by dots) at a
// boundary. No regex (cheap enough for the hot path). Gameplay lines never contain a dotted
// quad — positions are space-separated, decimals/build numbers have at most one dot — so this
// only ever fires on real IP-bearing lines.
bool ContainsIPv4(const char[] s)
{
    int len = strlen(s);
    for (int i = 0; i < len; i++)
    {
        if (!IsCharNumeric(s[i]))
            continue;
        // Require a left boundary so we start at the first digit of a run.
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

void BufferLine(const char[] message)
{
    if (!g_bHaveUrl || !g_cvEnabled.BoolValue)
        return;

    if (g_hBuffer.Length >= MAX_BUFFER_LINES)
    {
        // Endpoint unreachable / backed up — drop the backlog rather than grow unbounded.
        g_hBuffer.Clear();
        if (!g_bWarnedFull)
        {
            LogError("[logrelay] upload buffer full (endpoint unreachable?) — dropping backlog");
            g_bWarnedFull = true;
        }
        return;
    }

    char line[MAX_LINE];
    if (strncmp(message, "L ", 2) == 0)
    {
        strcopy(line, sizeof line, message);
    }
    else
    {
        // Build the canonical "L MM/DD/YYYY - HH:MM:SS:" prefix the receiver anchors on.
        char ts[32];
        FormatTime(ts, sizeof ts, "%m/%d/%Y - %H:%M:%S");
        Format(line, sizeof line, "L %s: %s", ts, message);
    }
    StripNewline(line);
    g_hBuffer.PushString(line);
}

// Buffer a synthetic "Loading map" line for the current map so the receiver always knows it,
// even when the plugin is (re)loaded mid-map (where OnMapStart never fires).
void BufferCurrentMap()
{
    if (!g_bHaveUrl || !g_cvEnabled.BoolValue)
        return;
    char map[PLATFORM_MAX_PATH];
    GetCurrentMap(map, sizeof map);
    if (map[0] == '\0')
        return;
    char line[MAX_LINE];
    Format(line, sizeof line, "Loading map \"%s\"", map);
    BufferLine(line);
    g_bMapAnnounced = true;
}

public Action Timer_Flush(Handle timer)
{
    if (!g_bHaveUrl || !g_cvEnabled.BoolValue)
    {
        if (g_hBuffer.Length)
            g_hBuffer.Clear();
        return Plugin_Continue;
    }

    // Announce the current map once after (re)load — covers loading the plugin mid-map, where
    // OnMapStart never fired, so the live view would otherwise show a blank map even when idle.
    if (!g_bMapAnnounced)
        BufferCurrentMap();

    if (g_hBuffer.Length == 0)
        return Plugin_Continue;

    char url[512];
    g_cvUrl.GetString(url, sizeof url);

    // Drain as many buffered lines as fit in one body; anything left rolls to the next tick.
    g_sBody[0] = '\0';
    int pos = 0;
    int sent = 0;
    char line[MAX_LINE];
    int n = g_hBuffer.Length;
    for (int i = 0; i < n; i++)
    {
        g_hBuffer.GetString(i, line, sizeof line);
        int len = strlen(line);
        if (pos + len + 1 >= sizeof g_sBody)
            break;
        pos += FormatEx(g_sBody[pos], sizeof g_sBody - pos, "%s\n", line);
        sent++;
    }
    if (sent == 0)
        return Plugin_Continue;

    for (int i = 0; i < sent; i++)
        g_hBuffer.Erase(0);

    g_bWarnedFull = false;
    SendBatch(url, g_sBody, pos);
    return Plugin_Continue;
}

// Resolve + cache this server's public connect address (ip:port). The SERVER IP is the public
// game address (not player PII); it lets the receiver identify which server a stream came from.
// Cached once Steam reports a non-zero public IP (it may be 0 for the first few seconds).
char g_sServerAddr[48];
void ResolveServerAddr()
{
    if (g_sServerAddr[0] != '\0')
        return;
    int ip[4];
    if (!SteamWorks_GetPublicIP(ip) || ip[0] == 0)
        return;
    int port = 27015;
    ConVar cv = FindConVar("hostport");
    if (cv != null && cv.IntValue > 0)
        port = cv.IntValue;
    Format(g_sServerAddr, sizeof g_sServerAddr, "%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port);
}

void SendBatch(const char[] url, const char[] body, int len)
{
    Handle req = SteamWorks_CreateHTTPRequest(k_EHTTPMethodPOST, url);
    if (req == null)
        return;

    char key[128];
    g_cvKey.GetString(key, sizeof key);
    if (key[0] != '\0')
        SteamWorks_SetHTTPRequestHeaderValue(req, "X-Api-Key", key);

    char sid[128];
    g_cvServerId.GetString(sid, sizeof sid);
    if (sid[0] == '\0' && g_cvHostname != null)
        g_cvHostname.GetString(sid, sizeof sid);
    if (sid[0] != '\0')
        SteamWorks_SetHTTPRequestHeaderValue(req, "X-Server-Id", sid);

    // Report this server's public connect address (ip:port) for stream identification. The SERVER
    // IP is the public game address, not player PII.
    ResolveServerAddr();
    if (g_sServerAddr[0] != '\0')
        SteamWorks_SetHTTPRequestHeaderValue(req, "X-Server-Addr", g_sServerAddr);

    SteamWorks_SetHTTPRequestRawPostBody(req, "text/plain", body, len);
    SteamWorks_SetHTTPRequestNetworkActivityTimeout(req, 10);

    // Every request handle is freed EXACTLY once: here if the callback can't be registered or the
    // send doesn't start (otherwise nothing would ever free it — no GC), else in OnHTTPComplete
    // when the request finishes (including on timeout/failure, which SteamWorks always reports).
    if (!SteamWorks_SetHTTPCallbacks(req, OnHTTPComplete) || !SteamWorks_SendHTTPRequest(req))
        delete req;
}

public int OnHTTPComplete(Handle req, bool failure, bool requestSuccessful, EHTTPStatusCode statusCode)
{
    if (g_cvDebug.BoolValue && (failure || !requestSuccessful || statusCode != k_EHTTPStatusCode200OK))
        LogMessage("[logrelay] upload failed (failure=%d success=%d status=%d)", failure, requestSuccessful, statusCode);

    delete req;
    return 0;
}

void StripNewline(char[] s)
{
    int l = strlen(s);
    while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r'))
        s[--l] = '\0';
}
