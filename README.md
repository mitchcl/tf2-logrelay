# tf2-logrelay (UDP / HMAC-SHA256)

The SourceMod plugin that streams live match stats to tf2esports.com. It blasts a Source/TF2
server's gameplay log over **UDP** to one or more recipients — like raw `logaddress`, but each
packet is **authenticated with HMAC-SHA256** (shared secret) and **stripped of PII** first.

It only *reads* the server's game log (never alters it), so logs.tf, SourceTV and normal logging
are unaffected.

> Canonical repo: **https://github.com/mitchcl/tf2-logrelay** (the HTTPS-POST prototype is on its
> `https` branch). This folder vendors the deployed build.

## Privacy

By default (**comprehensive mode**) it forwards every gameplay log line **except**:

- **IP addresses** — every line is scanned for a dotted-quad IPv4 and dropped if present, so a
  player IP can never leave the server (connection / rcon lines are the only ones that contain one).
- **Chat** — `say` / `say_team` are dropped unless `logrelay_send_chat 1`.

Set `logrelay_strict 1` to instead forward **only** an explicit gameplay whitelist. Player
identity in forwarded lines is SteamID + in-game name only — public scoreboard data. The guards
are `ContainsIPv4()` and `OnGameLog()` in
[the source](scripting/tf2_logrelay.sp).

## Requirements

- SourceMod 1.11+
- **Socket** extension (UDP transport)
- **cURL** extension (native OpenSSL hashing for the HMAC — no SHA is implemented in pawn)
- For full damage / accuracy / medic stats: SupStats2 + the logs.tf medic-stats plugin.

## Install

1. Copy `plugins/tf2_logrelay.smx` into the server's `tf/addons/sourcemod/plugins/`.
2. Change map, or `sm plugins load tf2_logrelay`.
3. Edit `tf/cfg/sourcemod/tf2_logrelay.cfg` (auto-generated on first run):
   ```
   logrelay_host "tf2esports.com"
   logrelay_port "8003"
   logrelay_key  "<shared secret>"
   ```
4. `sm plugins reload tf2_logrelay` (or change map). Inert until `logrelay_host`/`logrelay_port`/`logrelay_key` are set.

## ConVars

| ConVar | Default | Purpose |
| --- | --- | --- |
| `logrelay_enabled` | `1` | Master on/off. |
| `logrelay_host` | *(empty)* | UDP host/IP of the default recipient. Empty = inert. |
| `logrelay_port` | `0` | UDP port of the default recipient. |
| `logrelay_key` | *(empty)* | Shared secret used as the HMAC-SHA256 key. |
| `logrelay_server_id` | *(empty)* | Server id in each packet; falls back to the game `ip:port`. |
| `logrelay_strict` | `0` | `1` = whitelist only; `0` = everything except PII / chat. |
| `logrelay_send_chat` | `0` | `1` = also forward chat. |
| `logrelay_debug` | `0` | Log failures to the server console. |

## Multiple recipients (rcon)

Send to more than one destination (e.g. a casting org **and** tf2esports), each with its own key —
each gets its own HMAC'd packet. Manage them live from rcon / the server console; changes apply
immediately and persist across map changes and restarts:

```
logrelay_add <ip:port> <key>     add or update a recipient
logrelay_remove <ip:port>        remove one
logrelay_list                    list recipients (keys never printed)
logrelay_clear                   remove all
logrelay_reload                  re-read cvars + config
```

These are additive to the `logrelay_host/port/key` cvar recipient and persist to
`addons/sourcemod/configs/tf2_logrelay_recipients.cfg` (which you can also hand-edit — see the
[example](configs/tf2_logrelay_recipients.cfg.example) — then `logrelay_reload`).

## Wire format (for building a receiver)

One UDP datagram per log line:

```
<64-hex HMAC-SHA256><serverid>\x1f<hostname>\x1f<logline>
```

- First **64 chars** = `hex(HMAC_SHA256(key, payload))`, where `payload` is everything after them.
  The key is the raw `logrelay_key` string.
- `0x1f` (unit separator) splits the fields: `serverid` (`ip:port`), `hostname` (display name),
  and the plain HL-log line.

Receiver: `mac = packet[:64]`, `payload = packet[64:]`, verify `HMAC_SHA256(key, payload) == mac`
(constant-time), split `payload` on `0x1f`, key the stream by `serverid`. Node reference:

```js
const expected = crypto.createHmac('sha256', KEY).update(payload).digest('hex');
```

## Build

```
spcomp tf2_logrelay.sp
```
Minimal `logrelay_socket.inc` / `logrelay_curl.inc` are vendored next to the source (the upstream
`socket.inc` uses the removed `funcenum` syntax). A prebuilt `.smx` is in `plugins/`.

## Troubleshooting

- **`Required extension "SteamWorks"...` / `cannot open shared object file`** — that's the older
  HTTPS build; the UDP build needs **Socket** + **cURL** instead.
- **Nothing arrives** — `logrelay_debug 1`; the console then logs socket/HMAC failures. The plugin
  also logs `[logrelay] N recipient(s) configured` on load. A receiver-side `HMAC rejected` means
  the keys don't match.
