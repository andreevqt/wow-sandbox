# wow-sandbox

Learning project: a **World of Warcraft 1.12.1 (build 5875) server** written from scratch in Go, for reverse-engineering practice.

It implements the logon (SRP6 auth + realm list) and the start of the world protocol (auth handshake with session-key digest, encrypted packet headers, character enumeration). Validated against the real 1.12.1 client up to the character-creation screen.

## Status

| Milestone | State |
|-----------|-------|
| Logon: SRP6 auth + realm list | ✅ reaches realm/char screen |
| World M2: handshake + header crypt + char enum | ✅ reaches character screen |
| World M3–M5: char create, enter world, movement | ⬜ planned (the "побегать" goal) |

## Run

```sh
go run ./cmd/server
```

Starts both servers in one process, sharing the session-key store:
- logon on `:3724`
- world on `:8085`

A test account `TEST` / `TEST` is registered on startup. Point a 1.12.1 client
at it via `realmlist.wtf`:

```
set realmlist "127.0.0.1"
```

Log in with `TEST` / `TEST`, pick the **Sandbox** realm, and you reach the
character-selection screen. Creating a character / entering the world is not
implemented yet (M3–M5).

## Test

```sh
go test ./...
```

SRP6 round-trip, the logon flow, the world handshake (`net.Pipe`), and the
header cipher are all verified without needing the game client.

## Layout

```
cmd/server          entrypoint — runs logon (:3724) + world (:8085)
internal/packet     little-endian packet (de)serialization
internal/srp        WoW SRP6 (g=7, k=3, SHA1)
internal/account    in-memory account store
internal/session    shared account → session-key (K) store
internal/auth        logon session state machine
internal/world       world handshake, header cipher, char enum
```
