# wow-sandbox

Learning project: a World of Warcraft 1.12.1 (build 5875) logon server written from scratch in Go, for reverse-engineering practice.

Current scope is the logon/auth server only — SRP6 authentication plus a realm list. The world server (gameplay) is not built yet.

## Run

```sh
go run ./cmd/authserver
```

Listens on `:3724` and advertises one realm pointing at `127.0.0.1:8085`.
A test account `TEST` / `TEST` is registered on startup.

Point a 1.12.1 client at it via `realmlist.wtf`:

```
set realmlist "127.0.0.1"
```

Logging in reaches the character screen; selecting the realm then tries to
connect to the (not-yet-built) world server on `:8085`.

## Test

```sh
go test ./...
```
