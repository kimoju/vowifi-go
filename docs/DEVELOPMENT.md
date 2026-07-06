# Development

## Local Validation

Run the unit test suite:

```sh
go test ./...
```

Run the same local CI entry point as GitHub Actions:

```sh
make ci
```

Useful focused targets are:

- `make fmt-check`
- `make tidy-check`
- `make vet`
- `make test`
- `make race`
- `make download`
- `make compat-vohive`

If Go is installed outside `PATH`, pass it explicitly:

```sh
GO=/usr/local/go/bin/go make ci
```

## GitHub Actions

GitHub Actions runs `.github/workflows/ci.yml` on Ubuntu with the Go version
from `go.mod`, calling `scripts/ci.sh` for formatting, module tidiness, vet,
unit tests, and race tests.

The manual `.github/workflows/vohive-compat.yml` workflow checks this module
against an older VoHive consumer checkout. It asks for the VoHive repository
and an optional ref, then runs the same compatibility script used locally.

The current test suite uses loopback networking and mock command boundaries. It
does not require a modem, root privileges, or a real TUN device in CI.

## VoHive Workspace Usage

VoHive can use this repository through its workspace:

```go
replace github.com/boa-z/vowifi-go v1.1.2 => ../vowifi-go
```

## VoHive Compatibility Check

Run the compatibility guard against a local VoHive checkout:

```sh
VOHIVE_DIR=/path/to/vohive GO=/usr/local/go/bin/go make compat-vohive
```

The script clones or copies the VoHive checkout into a temporary directory,
rewrites legacy `vowifi-go` imports there when needed, injects a temporary
`replace` pointing at this repository, then runs the focused VoHive test set.
The source VoHive checkout is not modified.

Useful overrides:

- `VOHIVE_COMPAT_PACKAGES` changes the tested package list.
- `VOHIVE_COMPAT_RUN` changes the `go test -run` pattern.
- `VOHIVE_COMPAT_BUILD_PACKAGES` optionally adds `go build` package checks.
- `VOHIVE_COMPAT_TMPDIR` chooses the parent directory for temporary clones and
  Go build work.
- `VOWIFI_COMPAT_LEGACY_BASE` changes the legacy import owner/base rewritten
  inside the temporary VoHive copy.
