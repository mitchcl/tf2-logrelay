# tf2-logrelay (UDP / HMAC)

A SourceMod plugin that blasts a Source/TF2 server's gameplay log over **UDP** to a host of your
choice — like raw `logaddress`, but each packet is **authenticated with HMAC-SHA256** (shared
secret) and **stripped of PII** first. A privacy-respecting, drop-in-ish alternative to
`logaddress_add` that existing log ingesters (e.g. cheat feeds) can consume by adding a verify step.

It only *reads* the server's game log (never alters it), so logs.tf, SourceTV and normal logging
are unaffected.

> The original HTTPS-POST variant is on the [`https`](https://github.com/mitchcl/tf2-logrelay/tree/https) branch.

## Privacy

By default (**comprehensive mode**) it forwards every gameplay log line **except**:

- **IP addresses** — every line is scanned for a dotted-quad IPv4 and dropped if present, so an
  IP can never leave the server (connection / rcon lines are the only ones that contain one).
- **Chat** — `say` / `say_team` are dropped unless you set `logrelay_send_chat 1`.

Set `logrelay_strict 1` to instead forward **only** an explicit gameplay whitelist. Player
identity in forwarded lines is SteamID + in-game name only (public scoreboard data). The guards
are `ContainsIPv4()` and `OnGameLog()` in
[the source](addons/sourcemod/scripting/tf2_logrelay.sp) — audit them directly.

## Requirements

- SourceMod 1.11+
- **Socket** extension (UDP transport)
- **cURL** extension (native OpenSSL hashing for the HMAC — no SHA is implemented in pawn)
- For full damage / accuracy / medic stats: SupStats2 + the logs.tf medic-stats plugin.

## Install

1. Copy `addons/sourcemod/plugins/tf2_logrelay.smx` into `tf/addons/sourcemod/plugins/`.
2. Change map, or `sm plugins load tf2_logrelay`.
3. Edit `tf/cfg/sourcemod/tf2_logrelay.cfg` (auto-generated on first run):
   ```
   logrelay_host "your.receiver.host"
   logrelay_port "8003"
   logrelay_key  "<shared secret>"
   ```
4. `sm plugins reload tf2_logrelay` (or change map). Inert until `logrelay_host` + `logrelay_port` are set.

## ConVars

| ConVar | Default | Purpose |
| --- | --- | --- |
| `logrelay_enabled` | `1` | Master on/off. |
| `logrelay_host` | *(empty)* | UDP host/IP to send to. Empty = inert. |
| `logrelay_port` | `0` | UDP port to send to. |
| `logrelay_key` | *(empty)* | Shared secret used as the HMAC-SHA256 key. |
| `logrelay_server_id` | *(empty)* | Server id in each packet; falls back to the game port. |
| `logrelay_strict` | `0` | `1` = whitelist only; `0` = everything except PII / chat. |
| `logrelay_send_chat` | `0` | `1` = also forward chat. |
| `logrelay_debug` | `0` | Log socket/HMAC failures to the server console. |

## Packet format (for building a receiver)

One UDP datagram per log line:

```
<64-hex HMAC-SHA256><serverid>\x1f<hostname>\x1f<logline>
```

- The first **64 chars** are `hex(HMAC_SHA256(logrelay_key, payload))`, where `payload` is
  everything after them (`<serverid>\x1f<hostname>\x1f<logline>`). The key is the raw
  `logrelay_key` string.
- `0x1f` (unit separator) splits the fields; `serverid` is the server's `ip:port` (or `logrelay_server_id`),
  `hostname` is the server's display name, and the line is plain HL-log text.

Receiver: take `mac = packet[:64]`, `payload = packet[64:]`, verify
`HMAC_SHA256(key, payload) == mac` (constant-time), then split `payload` on `0x1f`. Key the
stream by `serverid` (falling back to `senderIP + serverid`). Node reference:

```js
const expected = crypto.createHmac('sha256', KEY).update(payload).digest('hex');
```

Existing logaddress tooling can consume the stream by stripping the 64-char tag + server-id field
(and optionally verifying the HMAC).

## Build

```
spcomp tf2_logrelay.sp
```
Minimal modern `logrelay_socket.inc` / `logrelay_curl.inc` are vendored next to the source because
the upstream `socket.inc` uses the removed `funcenum` syntax (rejected by the SM 1.12 compiler).
A prebuilt `.smx` is in `addons/sourcemod/plugins/`.

## License

MIT — see [LICENSE](LICENSE).
