# Client ↔ helper protocol

The GUI and CLI run as the normal user. Anything that needs root (finding devices,
unlocking, mounting, reading files on the target, quarantine) goes through the privileged
helper. The helper is started on demand: `pkexec <libdir>/offscan-helper`, or directly when
the client already runs as root. It talks to the client over its stdin/stdout. Each message
is one JSON object on one line, ASCII-encoded. The implementation is `src/offscan/protocol.py`.

## Framing

* Lines are at most 8 MiB. Longer lines are a protocol error and the connection is dropped.
* Only ASCII goes on the wire. Non-ASCII text, and filename bytes that are not valid UTF-8,
  are sent as `\uXXXX` escapes. Paths are strings decoded with Python's `surrogateescape`,
  so any byte sequence survives the round trip exactly.
* `NaN` and `Infinity` are rejected in both directions.

## Messages

| type | sent by | fields |
|---|---|---|
| `hello` | helper, first line | `protocol` (int), `version`, `pid` |
| `req` | client | `id` (int ≥ 0, unique per connection), `method`, `params` (object) |
| `res` | helper | `id`, `ok` (bool), `result` or `error` {`code`, `message`, `details`?} |
| `evt` | helper | `event`, `data`, optional `job` (int) |

Error codes: `invalid_request`, `unknown_method`, `invalid_params`, `not_permitted`,
`not_found`, `busy`, `failed`, `cancelled`, `internal`.

## Trust rules

* The helper validates every request against a declared parameter schema and rejects
  unknown parameters.
* Device arguments must come from the helper's own enumeration. Path arguments must be
  inside a mount the helper created.
* The client treats every string from the helper (filenames especially) as hostile, and
  escapes it before display (`offscan.names.display`).
* The helper exits when its stdin closes. It unmounts everything and restores block-device
  read-only flags first.

Methods are documented next to their handlers in `src/offscan/helper/`.
