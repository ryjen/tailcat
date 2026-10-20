package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineAttestationVerification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		breakSubject bool
		wantFailure  bool
	}{
		{"valid two-platform SBOM", false, false},
		{"forged attestation subject", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "oci.tar")
			if err := testOCIArchive(archive, tc.breakSubject); err != nil {
				t.Fatal(err)
			}
			err := verify(archive)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("verify() err = %v, wantFailure=%v", err, tc.wantFailure)
			}
		})
	}
}

func testOCIArchive(out string, breakSubject bool) error {
	blobs := map[string][]byte{}
	store := func(data any) descriptor {
		b, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}
		hash := sha256.Sum256(b)
		digest := "sha256:" + hex.EncodeToString(hash[:])
		blobs["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")] = b
		return descriptor{Digest: digest, Size: int64(len(b))}
	}
	images := []descriptor{}
	attests := []descriptor{}
	for _, arch := range []string{"amd64", "arm64"} {
		img := store(map[string]any{"schemaVersion": 2, "architecture": arch})
		img.Platform.OS, img.Platform.Architecture = "linux", arch
		images = append(images, img)
		subject := strings.TrimPrefix(img.Digest, "sha256:")
		if breakSubject && arch == "arm64" {
			subject = strings.Repeat("0", 64)
		}
		stmt := store(map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"predicateType": "https://spdx.dev/Document",
			"predicate":     map[string]any{"SPDXID": "SPDXRef-DOCUMENT", "packages": []any{map[string]any{"name": "sample"}}},
			"subject":       []any{map[string]any{"name": "_", "digest": map[string]any{"sha256": subject}}},
		})
		stmt.MediaType = "application/vnd.in-toto+json"
		stmt.Annotations = map[string]string{"in-toto.io/predicate-type": "https://spdx.dev/Document"}
		att := store(manifest{
			ArtifactType: "application/vnd.docker.attestation.manifest.v1+json",
			Subject:      img,
			Layers:       []descriptor{stmt},
		})
		att.Platform.OS, att.Platform.Architecture = "unknown", "unknown"
		att.Annotations = map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": img.Digest,
		}
		attests = append(attests, att)
	}
	root, err := json.Marshal(index{Manifests: append(images, attests...)})
	if err != nil {
		return err
	}
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := tar.NewWriter(file)
	defer writer.Close()
	blobs["index.json"] = root
	for name, b := range blobs {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b))}); err != nil {
			return err
		}
		if _, err := writer.Write(b); err != nil {
			return err
		}
	}
	return nil
}
