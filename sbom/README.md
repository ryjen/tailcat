# Tailcat dependency audit and CycloneDX SBOMs

These are **source-derived Go application SBOMs**, not attestations of released binaries or container images. They document the dependency upgrade proposed for [tailscale/tailcat#151](https://github.com/tailscale/tailcat/issues/151).

## Provenance

- Dependency upgrade revision: `3064e971bf46abc378b1bae9ccad83bcb374838d`. The SBOM root version is now a **stable digest of tracked Go sources**, `go.mod`, `go.sum`, `build-tags.txt` and `.goreleaser.yaml`, not a Git pseudoversion. `tailcat:source-inputs:sha256` records the full digest, binding every SBOM to those inputs across documentation-only commits.
- [`tool/sbom/sbom.go`](../tool/sbom/sbom.go) clones the current committed HEAD into a normal temporary checkout (Git linked worktrees are supported), uses the pinned generator, canonicalizes the root identity, and verifies the exact saved inventory. `go run ./tool/sbom check` fails if an SBOM is stale. The [supply-chain workflow](../.github/workflows/supply-chain.yml) runs on PRs and pushes to main.
- Go: `1.27.2`. SBOM generator: [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) **v1.12.0**, downloaded as a checksum-verified release binary and run outside this module; Linux amd64 archive SHA-256: `004b9f5cc595b797fb5423e2ae4c97bcf0f18c712ed2faee1640b09e5efd6d15`. The workflow verifies this checksum before execution. **No generator dependency was added to `go.mod`**.
- CycloneDX 1.6 JSON. The generator omits serial numbers and generation timestamps. Component hashes represent Go's module checksum scheme, not a vendor signature.
- Entry point `./cmd/tailcat`; `CGO_ENABLED=0`, release build tags in `build-tags.txt`, and matching `GOOS`/`GOARCH`/`GOARM` from `.goreleaser.yaml`.
- All third-party components have automatically detected license **evidence**. The `std@go1.27.2` component is added by `-std`; its BSD-3-Clause evidence is assigned explicitly by the normalization script after comparison with the [Go 1.27.2 source LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.27.2/LICENSE). This is not a legal approval of each license.

The source inputs for these snapshots have SHA-256 hashes:

| File | SHA-256 |
| --- | --- |
| `go.mod` | `3687ce7512de7d61b1d38d368f5fd138bde9dd2195509abdc41a48bf263398a8` |
| `go.sum` | `52ce5fc33db529da4eb2e0d8e88e1e495e740df396d4c0af5afd9fe990b0ef52` |
| `build-tags.txt` | `9c2e72b07fb396f577a57ebc5bbedb68ce29552d5dfd63bd9cbced474197fcfe` |

| SBOM file | Target | Dependency components |
| --- | --- | ---: |
| `tailcat-linux-amd64.cdx.json` | linux/amd64 | 39 |
| `tailcat-linux-arm64.cdx.json` | linux/arm64 | 39 |
| `tailcat-linux-arm.cdx.json` | linux/arm/v7 | 39 |
| `tailcat-windows-amd64.cdx.json` | windows/amd64 | 36 |
| `tailcat-windows-arm64.cdx.json` | windows/arm64 | 36 |

These totals include the Go standard library as a component. They therefore exceed the previously counted third-party Go modules by one.

## Dependency review

A comparison of `go list -m all` on the previous commit (`52fbad323e9d352f1febb623e0975368e9a8cbdd`) and the upgraded commit (`3064e971bf46abc378b1bae9ccad83bcb374838d`) yielded **675 selected modules** in each graph: **2 added**, **2 removed**, and **31 version changes**.

The added graph-only selections are `github.com/bradfitz/reco@v0.0.0-20260929154613-b883fbd17e3f` (BSD-3-Clause) and `github.com/tailscale/tb@v0.0.0-20261001153419-d666f92605bc` (BSD-3-Clause). The removed entries are `github.com/bradfitz/go-tool-cache` and `gopkg.in/square/go-jose.v2`. The newly explicit indirect `go.mod` requirement for `github.com/benbjohnson/immutable@v0.4.3` (MIT) was already present in the prior selected graph.

Across **all five supported release targets**, **zero modules were added to or removed from the compiled executable**. The same three version upgrades appear in each:

| Runtime module | Prior version | New version | Detected license |
| --- | --- | --- | --- |
| `tailscale.com` | `v1.103.0-pre.0.20260929142145-a0e471a35b8f` | `v1.105.0-pre.0.20261013225543-fb79793d99f5` | BSD-3-Clause |
| `github.com/tailscale/wireguard-go` | `v0.0.0-20260924224943-0a83b87f7908` | `v0.0.0-20260928213353-e61b6b78110b` | MIT |
| `golang.org/x/net` | `v0.59.0` | `v0.60.0` | BSD-3-Clause |

The WireGuard-Go range contains two changes: replay-filter drop accounting and serialized nonce stamping before outbound enqueue. x/net v0.60.0 contains HTTP/2 and QUIC implementation changes. The broad pre-release Tailscale module upgrade is the main compatibility risk, and contains the netstack shutdown fix from [tailscale/tailscale#21668](https://github.com/tailscale/tailscale/pull/21668).

## Security evidence and limitations

- `go mod verify` passed for both old and new module sets.
- On **2026-10-19**, `govulncheck v1.9.0` at **symbol** level found **no reachable vulnerability** in any of the five release target configurations (Linux amd64, arm64, arm/v7; Windows amd64, arm64), with `CGO_ENABLED=0` and all release tags. These are source-based reachability results, not binary vulnerability attestations. The Go vulnerability database recorded by the previous scan was last modified **2026-10-08**.
- A separate **module-level** finding, [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), concerns the unmaintained `golang.org/x/crypto/openpgp` package. `golang.org/x/crypto` is unchanged at `v0.57.0`; that OpenPGP package is not imported by the checked application. Keep it tracked as pre-existing dependency hygiene risk.
- A separate [550-session close regression](https://github.com/ryjen/tailcat/pull/2) reproduces the old shutdown hang and passes using the updated dependency.
- The BOMs describe selected Go source dependencies for the specified build settings. They **exclude OS packages, Docker image contents, build tool dependencies, and verification of exact final release binary contents**. Generated license matches need human review.
- **Source SBOM, Go test/cross-build, and Nix GitHub Actions workflows passed at dependency PR head 84645457b58f1e3a5b66f48d7ebb0d9a4ca25ecf**, including five-target vulnerability scanning. The Go-tooling migration needs to be requalified at its own final head. Publish separate binary-derived SBOMs alongside final release artifacts, and scan released container images independently. The release workflow currently does **not** attach SBOMs to binary/package/container artifacts.

## Regeneration and CI verification

The SBOM helper is a standard-library-only Go command under `tool/sbom/`, alongside the existing Go tools. Install the separately pinned `cyclonedx-gomod v1.12.0` tool on `PATH` and use Go 1.27.2. For Linux amd64, verify the published release archive against SHA-256
`004b9f5cc595b797fb5423e2ae4c97bcf0f18c712ed2faee1640b09e5efd6d15` before unpacking. The repository introduces no runtime module to produce SBOMs.

```sh
go run ./tool/sbom generate   # updates five source SBOMs
go run ./tool/sbom check      # fails when inventory or source digest drifts
```

Both Go commands work from a normal checkout or an existing Git worktree by using a disposable local checkout at HEAD, and clean up afterward. The source digest includes tracked Go sources, module manifest/lock, build tags and GoReleaser config but **excludes SBOMs themselves**, avoiding self-referential hashes. Changed Go sources require SBOM regeneration even if their dependencies are unchanged. The CI workflow checks this digest and scans vulnerabilities on the **five release-target configurations**.

## Release qualification follow-up

Source-derived SBOMs are a PR review and drift-detection artifact, **not a substitute for shipping exact binary-derived SBOMs**, OCI image SBOMs, or SLSA provenance. The release workflow must publish and associate final binary/package/image inventories with artifact digests before treating supply-chain release qualification as complete. Do not silently treat this source-only workflow as proof that shipped artifacts were scanned.
