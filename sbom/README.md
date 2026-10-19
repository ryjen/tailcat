# Tailcat dependency audit and CycloneDX SBOMs

These are **source-derived Go application SBOMs**, not attestations of released binaries or container images. They document the dependency upgrade proposed for [tailscale/tailcat#151](https://github.com/tailscale/tailcat/issues/151).

## Provenance

- Audited source revision: `3064e971bf46abc378b1bae9ccad83bcb374838d`. SBOM/documentation-only commits following that revision do not change application Go sources or dependency versions.
- Go: `1.27.2`. SBOM generator: [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) **v1.12.0**, downloaded as a checksum-verified official release and run outside this module; **no new SBOM tooling dependency was added to `go.mod`**.
- CycloneDX 1.6 JSON. The generator omits serial numbers and generation timestamps. Component hashes represent Go's module checksum scheme, not a vendor signature.
- Entry point `./cmd/tailcat`; `CGO_ENABLED=0`, release build tags in `build-tags.txt`, and matching `GOOS`/`GOARCH`/`GOARM` from `.goreleaser.yaml`.
- All listed dependency components have detected license **evidence**. This is not a legal approval of each license.

The source inputs for these snapshots have SHA-256 hashes:

| File | SHA-256 |
| --- | --- |
| `go.mod` | `3687ce7512de7d61b1d38d368f5fd138bde9dd2195509abdc41a48bf263398a8` |
| `go.sum` | `52ce5fc33db529da4eb2e0d8e88e1e495e740df396d4c0af5afd9fe990b0ef52` |
| `build-tags.txt` | `9c2e72b07fb396f577a57ebc5bbedb68ce29552d5dfd63bd9cbced474197fcfe` |

| SBOM file | Target | Dependency components |
| --- | --- | ---: |
| `tailcat-linux-amd64.cdx.json` | linux/amd64 | 38 |
| `tailcat-linux-arm64.cdx.json` | linux/arm64 | 38 |
| `tailcat-linux-arm.cdx.json` | linux/arm/v7 | 38 |
| `tailcat-windows-amd64.cdx.json` | windows/amd64 | 35 |
| `tailcat-windows-arm64.cdx.json` | windows/arm64 | 35 |

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
- `govulncheck v1.9.0` (Go vulnerability database last updated **2026-10-08**) found **no identified reachable symbol-level vulnerability** in the checked Tailcat application. One **module-level finding**, [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), concerns the unmaintained `golang.org/x/crypto/openpgp` package. `golang.org/x/crypto` is unchanged at `v0.57.0`, and the OpenPGP package is not imported by the checked application. This is pre-existing risk, not introduced by the upgrade.
- A separate [550-session close regression](https://github.com/ryjen/tailcat/pull/2) reproduces the old shutdown hang and passes using the updated dependency.
- The BOMs describe selected Go source dependencies for the specified build settings. They **exclude OS packages, Docker image contents, build tool dependencies, and verification of exact final release binary contents**. Generated license matches need human review.
- **Nix qualification, cross-platform compilation and GitHub Actions remain unverified.** Publish separate binary-derived SBOMs alongside final release artifacts, and scan released container images independently.

## Regeneration

Install the **separately pinned** `cyclonedx-gomod v1.12.0` tool (outside this module). From a normal Git checkout of the **reviewed source commit**, with Go 1.27.2:

```sh
export CGO_ENABLED=0
export GOFLAGS="-tags=$(cat build-tags.txt)"
for target in linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64; do
    os=${target%/*}
    arch=${target#*/}
    export GOOS="$os" GOARCH="$arch" GOARM=7
    cyclonedx-gomod app -main cmd/tailcat -json -licenses \
        -noserial -notimestamp \
        -output "sbom/tailcat-$os-$arch.cdx.json" .
done
```

The root application's Git pseudoversion is based on the checkout revision. Regenerate for subsequent dependency/source changes and compare component inventories. These source SBOMs do **not** replace release binary SBOMs.
