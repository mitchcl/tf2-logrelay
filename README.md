# tf2-logrelay

A SourceMod plugin that forwards a Source/TF2 server's gameplay log to an HTTPS endpoint of
your choice — **without ever sending player IP addresses or chat**. A privacy-respecting,
opt-in alternative to raw `logaddress_add`.

It only *reads* the server's game log (it never alters it), so logs.tf, SourceTV and normal
logging are unaffected. Point it at any compatible receiver (the wire format is below).

## Privacy

By default (**comprehensive mode**) it forwards every gameplay log line **except**:

- **IP addresses** — every line is scanned for a dotted-quad IPv4 and dropped if present, so an
  IP can never leave the server (connection / rcon lines are the only ones that contain one).
- **Chat** — `say` / `say_team` are dropped unless you set `logrelay_send_chat 1`.

Set `logrelay_strict 1` to instead forward **only** an explicit gameplay whitelist (kills,
damage, heals, ubers, caps, round/match events). The guards are `ContainsIPv4()` and
`OnGameLog()` in [the source](addons/sourcemod/scripting/tf2_logrelay.sp) — audit them directly.
Player identity in forwarded lines is SteamID + in-game name only (public scoreboard data). The
server's own public `ip:port` is sent in a header for stream identification — that's the public
game address, not player PII.

## Requirements

- SourceMod 1.11+
- [SteamWorks](https://github.com/KyleSanderson/SteamWorks) extension
- For full damage / accuracy / medic stats: SupStats2 + the logs.tf medic-stats plugin.
  Without them you still get kills, caps and round/match events.

## Install

1. Copy `addons/sourcemod/plugins/tf2_logrelay.smx` into your server's
   `tf/addons/sourcemod/plugins/`.
2. Change map, or `sm plugins load tf2_logrelay`.
3. Edit `tf/cfg/sourcemod/tf2_logrelay.cfg` (auto-generated on first run):
   ```
   logrelay_url  "https://your-receiver.example/ingest"
   logrelay_key  "<your shared secret>"
   ```
4. `sm plugins reload tf2_logrelay` (or change map). The plugin is inert until `logrelay_url`
   is set, and it must be `https://`.

## ConVars

| ConVar | Default | Purpose |
| --- | --- | --- |
| `logrelay_enabled` | `1` | Master on/off. |
| `logrelay_url` | *(empty)* | HTTPS endpoint to POST batched lines to. Empty = inert. |
| `logrelay_key` | *(empty)* | Sent as the `X-Api-Key` header. |
| `logrelay_server_id` | *(empty)* | Sent as `X-Server-Id`; falls back to `hostname`. |
| `logrelay_flush_interval` | `2.0` | Seconds between uploads. |
| `logrelay_strict` | `0` | `1` = whitelist only; `0` = everything except PII / chat. |
| `logrelay_send_chat` | `0` | `1` = also forward chat. |
| `logrelay_debug` | `0` | Log upload failures to the server console. |

## Wire format (for building a receiver)

Each flush is a single `POST` to `logrelay_url` with `Content-Type: text/plain`, body =
newline-delimited canonical log lines:

```
L 06/24/2026 - 21:00:00: "player<3><[U:1:1234]><Red>" killed "other<5><[U:1:5678]><Blue>" with "scattergun" (customkill "headshot")
L 06/24/2026 - 21:00:01: World triggered "Round_Win" (winner "Red")
```

Headers:

| Header | Value |
| --- | --- |
| `X-Api-Key` | your shared secret (`logrelay_key`) |
| `X-Server-Id` | stable per-server id (`logrelay_server_id` or `hostname`) |
| `X-Server-Addr` | the server's public `ip:port` (when resolvable) |

Your receiver should authenticate `X-Api-Key`, split the body on `\n`, and parse each line as a
standard HL-log-standard line keyed by `X-Server-Id`. Respond `200` to acknowledge.

## Build

```
spcomp tf2_logrelay.sp
```
with the SteamWorks include on the include path. A prebuilt `.smx` is in
`addons/sourcemod/plugins/`.

## Troubleshooting

- **`Required extension "SteamWorks" file("SteamWorks.ext") not running`** / **`cannot open
  shared object file`** — SteamWorks needs `libsteam_api.so` (32-bit) on the runtime library
  path. On most setups srcds provides it; if not, ensure the server launches via `srcds_run`
  (which puts `bin/` on `LD_LIBRARY_PATH`) or that `libsteam_api.so` is otherwise resolvable.
- **Nothing arrives** — set `logrelay_debug 1`; the console then logs upload failures (auth,
  TLS, network). Silence means the plugin isn't sending (check `logrelay_url`/`logrelay_key`
  and that gameplay is actually happening).

## License

MIT — see [LICENSE](LICENSE).
