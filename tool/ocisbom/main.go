// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// ocisbom verifies offline BuildKit SPDX SBOM attestations in a multi-platform
// OCI layout tarball. It neither contacts registries nor publishes artifacts.
// Usage: go run ./tool/ocisbom /path/to/image.oci.tar
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxJSON = 32 << 20

type descriptor struct {
	Digest      string            `json:"digest"`
	MediaType   string            `json:"mediaType"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
	Platform    struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

type index struct {
	Manifests []descriptor `json:"manifests"`
}
type manifest struct {
	ArtifactType string       `json:"artifactType"`
	Subject      descriptor   `json:"subject"`
	Config       descriptor   `json:"config"`
	Layers       []descriptor `json:"layers"`
}
type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		SPDXID   string            `json:"SPDXID"`
		Packages []json.RawMessage `json:"packages"`
	} `json:"predicate"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./tool/ocisbom IMAGE.oci.tar")
		os.Exit(2)
	}
	if err := verify(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "OCI SBOM verification failed:", err)
		os.Exit(1)
	}
}

func readArchive(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := tar.NewReader(f)
	blobs := map[string][]byte{}
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		if h.Name != "index.json" && !strings.HasPrefix(h.Name, "blobs/sha256/") {
			continue
		}
		if h.Size < 0 || h.Size > maxJSON {
			continue
		} // skip large compressed image layers
		if _, exists := blobs[h.Name]; exists {
			return nil, fmt.Errorf("duplicate tar member %s", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(t, h.Size))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) != h.Size {
			return nil, fmt.Errorf("truncated %s", h.Name)
		}
		blobs[h.Name] = b
	}
	if blobs["index.json"] == nil {
		return nil, errors.New("no OCI index.json")
	}
	return blobs, nil
}

func load(blobs map[string][]byte, digest string, v any) error {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return fmt.Errorf("invalid sha256 digest %q", digest)
	}
	raw, ok := blobs["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")]
	if !ok {
		return fmt.Errorf("OCI blob missing or too large: %s", digest)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != strings.TrimPrefix(digest, "sha256:") {
		return fmt.Errorf("OCI blob SHA-256 mismatch: %s", digest)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid blob JSON %s: %w", digest, err)
	}
	return nil
}

func verify(path string) error {
	blobs, err := readArchive(path)
	if err != nil {
		return err
	}
	var idx index
	if err := json.Unmarshal(blobs["index.json"], &idx); err != nil {
		return err
	}
	if len(idx.Manifests) == 0 {
		return errors.New("empty OCI index")
	}
	// OCI layout index.json may wrap a single multi-platform image index.
	// In that case unwrap the referenced, digest-verified child index.
	if len(idx.Manifests) == 1 && idx.Manifests[0].MediaType == "application/vnd.oci.image.index.v1+json" {
		var nested index
		if err := load(blobs, idx.Manifests[0].Digest, &nested); err != nil {
			return err
		}
		idx = nested
	}
	platforms := map[string]string{}
	imageManifests := map[string]manifest{}
	attestations := map[string][]descriptor{}
	for _, d := range idx.Manifests {
		ref := d.Annotations["vnd.docker.reference.type"]
		if ref == "attestation-manifest" {
			subject := d.Annotations["vnd.docker.reference.digest"]
			if subject == "" {
				return errors.New("attestation descriptor missing subject")
			}
			if d.Platform.OS != "unknown" || d.Platform.Architecture != "unknown" {
				return errors.New("attestation descriptor must be unknown/unknown")
			}
			attestations[subject] = append(attestations[subject], d)
			continue
		}
		if ref != "" {
			return fmt.Errorf("unsupported attestation reference %s", ref)
		}
		name := d.Platform.OS + "/" + d.Platform.Architecture
		if name != "linux/amd64" && name != "linux/arm64" {
			return fmt.Errorf("unexpected OCI runnable platform: %s", name)
		}
		if platforms[name] != "" {
			return fmt.Errorf("duplicate platform %s", name)
		}
		var img manifest
		if err := load(blobs, d.Digest, &img); err != nil {
			return err
		}
		platforms[name] = d.Digest
		imageManifests[name] = img
	}
	if len(platforms) != 2 {
		return fmt.Errorf("expected exactly two Linux image platforms; got %v", platforms)
	}
	if len(attestations) != 2 {
		return fmt.Errorf("expected attestations for exactly two subjects; got %d", len(attestations))
	}
	for _, name := range []string{"linux/amd64", "linux/arm64"} {
		digest := platforms[name]
		descs := attestations[digest]
		if len(descs) != 1 {
			return fmt.Errorf("%s has %d attestation manifests, want 1", name, len(descs))
		}
		var a manifest
		if err := load(blobs, descs[0].Digest, &a); err != nil {
			return err
		}
		if a.ArtifactType != "" && a.ArtifactType != "application/vnd.docker.attestation.manifest.v1+json" {
			return fmt.Errorf("%s has unrecognized attestation artifact type %s", name, a.ArtifactType)
		}
		if a.Subject.Digest != "" && a.Subject.Digest != digest {
			return fmt.Errorf("%s subject digest differs from image manifest", name)
		}
		// BuildKit attestation statement subjects can refer to the
		// final manifest or a cryptographically named object within that
		// manifest. The index descriptor and attestation manifest subject
		// are *both* required to bind to the platform manifest above.
		allowed := map[string]bool{strings.TrimPrefix(digest, "sha256:"): true}
		img := imageManifests[name]
		if strings.HasPrefix(img.Config.Digest, "sha256:") {
			allowed[strings.TrimPrefix(img.Config.Digest, "sha256:")] = true
		}
		for _, layer := range img.Layers {
			if strings.HasPrefix(layer.Digest, "sha256:") {
				allowed[strings.TrimPrefix(layer.Digest, "sha256:")] = true
			}
		}
		found := 0
		for _, l := range a.Layers {
			if l.MediaType != "application/vnd.in-toto+json" {
				continue
			}
			if l.Annotations["in-toto.io/predicate-type"] != "https://spdx.dev/Document" {
				continue
			}
			var stmt statement
			if err := load(blobs, l.Digest, &stmt); err != nil {
				return err
			}
			if stmt.PredicateType != "https://spdx.dev/Document" || stmt.Predicate.SPDXID != "SPDXRef-DOCUMENT" || len(stmt.Predicate.Packages) == 0 {
				return fmt.Errorf("%s SPDX attestation empty or invalid", name)
			}
			bound := false
			actualSubjects := []string{}
			for _, sub := range stmt.Subject {
				value := sub.Digest["sha256"]
				actualSubjects = append(actualSubjects, value)
				if allowed[value] && value != "" {
					bound = true
				}
			}
			if !bound {
				return fmt.Errorf("%s SPDX statement subjects %v do not match the image manifest/config/layers", name, actualSubjects)
			}
			found++
		}
		if found != 1 {
			return fmt.Errorf("%s has %d matching SBOM statements, want exactly 1", name, found)
		}
		fmt.Printf("verified %s image manifest %s with digest-bound SPDX SBOM\n", name, digest)
	}
	idxSum := sha256.Sum256(blobs["index.json"])
	fmt.Printf("verified offline OCI index sha256:%x (not a published registry digest)\n", idxSum)
	return nil
}
