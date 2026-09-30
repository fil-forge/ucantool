# ucantool

CLI and small Go library for working with UCAN 1.0 tokens: issue delegations,
pack tokens into containers, generate Ed25519 identities, and pretty-print any
token. It is the tool `smelt make init` uses to mint the proofs that let Forge
services authorize each other, so its output must stay decodable by every
other Forge service.

Module: `github.com/fil-forge/ucantool` (Go 1.25). Built on
`github.com/fil-forge/ucantone` (UCAN primitives: `did`, `multikey`,
`ucan/delegation`, `ucan/invocation`, `ucan/receipt`, `ucan/container`). No
libforge dependency. Cobra CLI; no viper, no config file, no env vars.

## Commands

- Build / vet / test: `go build ./... && go vet ./... && go test ./...`. This
  is the standard loop; there is no Makefile.
- Single test: `go test ./pkg/ucandelegate/ -run TestName`.
- Run locally: `go run . view container.bin`, `go run . identity generate`.
- Regenerate fixtures: `go run ./testing/gen/container > container.bin` and
  `go run ./testing/gen/invocation`. These are standalone generators, not
  tests; nothing in `go test` depends on the `.bin` output.
- CI runs `go-test` and `go-check` (vet / staticcheck / tidy via the ipdxco
  unified workflows); Windows and 32-bit are skipped. Dependabot patch and
  minor bumps auto-merge.
- **go.work caveat**: `/Users/alan/Code/fil-forge/go.work` includes both
  `./ucantool` and `./ucantone`, so local builds resolve ucantone from the
  sibling checkout, while CI uses the pseudo-version pinned in `go.mod`. Run
  `GOWORK=off go test ./...` before pushing to reproduce CI resolution.

## Layout

- `main.go` — calls `cmd.Execute()`; nothing else.
- `cmd/root.go` — `rootCmd`; subcommands register themselves in `init()`.
- `cmd/delegate.go` — `delegate` (alias `d`). Flag binding and I/O only; the
  logic lives in `pkg/ucandelegate`.
- `cmd/view.go` — `view` (alias `p`). Decodes container → invocation →
  delegation and prints a table, or DAG-JSON with `--json`.
- `cmd/identity/` — `identity generate` (aliases `id` / `gen`).
- `cmd/container/` — `container pack` (alias `c`).
- `pkg/ucandelegate` — the importable API (`Request`, `Issue`, `IssueFromPEM`,
  `Result.WriteTo`, `ExpiresIn` / `ExpiresAt`). Documented in the README's
  "Use as a library" section; keep the README in sync with its surface.
- `pkg/identity` — PKCS#8 PEM encode / decode for Ed25519 signers.
- `pkg/ucanfmt` — container codec parsing (`ParseCodec`, `IsTextualCodec`,
  `DefaultContainerCodec = "base64+gzip"`) and the table formatters.
- `pkg/ipldfmt` — DAG-JSON formatting with chroma highlighting, gated on
  `term.IsTerminal(os.Stdout)` so piped output stays plain.
- `testing/gen/` — fixture generators (see Commands).

## Conventions

- **CLI / library split**: `cmd/` binds flags and does I/O; anything a caller
  might want without touching disk goes in `pkg/`. `pkg/ucandelegate` exists so
  a caller never has to write a private key to a file.
- **Output discipline**: textual codecs get a trailing newline; `raw` and
  `raw+gzip` are written bare so the bytes round-trip through
  `delegation.Decode`. Write to `cmd.OutOrStdout()`, never `fmt.Print`
  (`cmd.Println` goes to stderr). `identity generate` prints the PEM to stdout
  and the DID to stderr as `# <did>`. Tests cover this in three places; keep
  them passing.
- **Errors**: `fmt.Errorf("parsing audience DID: %w", err)` style (lowercase
  gerund phrase, wrap with `%w`). Commands use `RunE` with
  `SilenceUsage: true`; every command sets `Args`.
- **Flags**: every flag has a short form. `-o` means output codec on both
  `delegate --container` and `container pack --codec`.
- **Expiration**: a nil `Request.Expiration` is passed explicitly as
  `delegation.WithNoExpiration()`. Omitting the option would give ucantone's
  30-second default. Past expirations are rejected.
- **Decode-by-trial order matters**: `container pack` tries receipt before
  invocation because a receipt is structurally an invocation. Reordering
  silently misclassifies receipts.
- **Tests**: `testify/require`, `t.Run` subtests, `t.TempDir()`, fresh keys
  generated in-process (never the working tree's `id.pem`), helpers from
  `ucantone/testutil`. `cmd/delegate_test.go` is in-package so it can reset
  the flag globals cobra keeps between `Execute` calls; do the same for any
  new command test.
- Commits follow Conventional Commits (`feat:`, `fix:`, `refactor:`,
  `chore(deps):`).

## Security

Key material is sensitive. `*.pem` and `*.bin` are gitignored; the `id.pem`
often present in the working tree is a real dev private key. **Never `cat`,
echo, log, or commit it, and never format key bytes into an error or test
output**; errors in `pkg/identity` reference `signer.KeyDID()` only (see commit
`9c54728`). Use `ucantool identity generate` for throwaway keys in examples.

## Gotchas / blast radius

- Container and delegation bytes this tool emits are consumed by every Forge
  service (smelt's `make init` proof top-up, ingot, hilt, sprue, piri). Changes
  to encoding, codec names, or default codec are wire changes; coordinate.
- `pkg/ipldfmt` panics on marshal / highlight errors by design (formatting is
  treated as infallible). Do not wrap it in error returns without a reason.
- `container.bin` in the working tree is the base64 container the README's
  `view --json` example decodes; regenerate it rather than editing by hand.
