# wow-sandbox

Learning project: a **World of Warcraft 1.12.1 (build 5875) server** written from scratch in Go, for reverse-engineering practice.

It implements the logon (SRP6 auth + realm list) and the start of the world protocol (auth handshake with session-key digest, encrypted packet headers, character enumeration). Validated against the real 1.12.1 client up to the character-creation screen


## Run

```sh
go run ./cmd/server
```

Starts both servers in one process, sharing the session-key store:
- logon on `:3724`
- world on `:8085`

```
set realmlist "127.0.0.1"
```

## Test

```sh
go test ./...
```
