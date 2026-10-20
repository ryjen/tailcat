# Releasing tailcat

Releases are cut by pushing a version tag. GitHub Actions
(`.github/workflows/release.yml`) then runs
[GoReleaser](https://goreleaser.com/) with the config in
`.goreleaser.yaml`, which builds the artifacts and creates a draft
GitHub Release with a changelog generated from the commit log. The
draft is invisible to watchers until published.

## Cutting a release

1. Make sure the Test workflow is green on `main`.
2. Run the release script, which creates an SSH-signed annotated tag
   after checking that the tag doesn't already exist on origin (a tag
   that exists only locally is replaced). It requires git's
   `user.signingkey` to be set to your SSH public key.

   ```sh
   ./tag.sh v0.1.0
   ```

3. Push the tag as the script instructs:

   ```sh
   git push origin v0.1.0
   ```

4. Watch the Release workflow in the Actions tab. When it finishes,
   a draft release with all artifacts appears on the
   [Releases page](https://github.com/tailscale/tailcat/releases).

5. Edit the draft: replace or top it with hand-written release notes,
   then publish. Publishing is the step that notifies watchers, so
   the notification carries the curated notes.

## Artifacts

Each release contains:

* Linux static binaries (tar.gz) for amd64, arm64, and armv7
* Debian (.deb) and RPM (.rpm) packages for the same architectures
* Windows binaries (zip) for amd64 and arm64
* `checksums.txt` with SHA-256 checksums of the above **and all generated SBOM files**
* CycloneDX JSON SBOMs produced by Syft from each compiled binary, archive
  and Debian/RPM package. These are artifact-derived, separate from
  source-derived dependency inventories used during pull-request review.

Each release also pushes container images (amd64 and arm64) to
[ghcr.io/tailscale/tailcat](https://github.com/tailscale/tailcat/pkgs/container/tailcat), tagged
both `vX.Y.Z` and `latest`. The image is the static binary in a
[distroless](https://github.com/GoogleContainerTools/distroless) base
image; see `Dockerfile.goreleaser`. GoReleaser's `dockers_v2` uses
buildx to attach SBOM attestations to the pushed multi-platform image.
For verification, resolve and inspect the image by immutable digest,
not merely the mutable `latest` tag.

The binary version is embedded at build time via `-ldflags -X
main.version=...`; `tailcat version` prints it. Builds made with
`go install github.com/tailscale/tailcat/cmd/tailcat@vX.Y.Z` instead
report the module version from the Go build info.

## Testing locally

To build everything without tagging or publishing, install
[GoReleaser](https://goreleaser.com/install/) and run:

```sh
goreleaser release --snapshot --clean
```

The artifacts land in `dist/` (which is gitignored). In snapshot mode
the container images are built into the local Docker daemon as
separate per-platform tags rather than a multi-arch manifest, and
nothing is pushed. Building them requires a buildx builder with the
docker-container driver (`docker buildx create --use`).


## Artifact SBOM qualification

The release workflow installs Syft **v1.54.1** from a SHA-256-verified
archive, then GoReleaser **v2.18.3**. Missing or invalid Syft must fail
the release instead of silently omitting its inventories.

GoReleaser generates SBOMs for archives, standalone compiled binaries, and
nFPM Debian/RPM packages. Each SBOM is named for the artifact and uploaded
as a release asset. The `checksums.txt` file records SHA-256 digests for released artifacts
and all 16 generated SBOM files. Check each downloaded artifact and its
matching `.sbom.json` against this manifest, and verify that both belong
to the intended release. The checksum file alone is **not** a
cryptographically signed attestation of who built those artifacts.

The multi-platform OCI image uses buildx's independent SBOM attestation
(`dockers_v2.sbom: true`); confirm the attestation exists for both
`linux/amd64` and `linux/arm64` on the **published digest**.
Archive/package SBOMs do not include the distroless base image.

For a **non-publishing** rehearsal with GoReleaser, use its snapshot or
skip-publish mode and examine `dist/` SBOMs before pushing any version tag.
A local rehearsal cannot validate remote GHCR registry permissions,
image attestation publication, or signed release provenance. Do not
treat those as complete without a verified staged release.
