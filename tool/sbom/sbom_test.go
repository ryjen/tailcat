// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
)

func fixture() map[string]any {
	const old = "v0.0.0-20261019212044-35b221f20b39"
	root := "pkg:golang/github.com/tailscale/tailcat@" + old + "?type=module#cmd/tailcat"
	return map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"metadata": map[string]any{"component": map[string]any{
			"version": old,
			"bom-ref": root,
			"purl":    "pkg:golang/github.com/tailscale/tailcat@" + old + "?goarch=amd64&goos=linux&type=module#cmd/tailcat",
			"properties": []any{
				map[string]any{"name": "cdx:gomod:build:env:CGO_ENABLED", "value": "0"},
				map[string]any{"name": "cdx:gomod:build:env:GOOS", "value": "linux"},
				map[string]any{"name": "cdx:gomod:build:env:GOARCH", "value": "amd64"},
				map[string]any{"name": "cdx:gomod:build:env:GOVERSION", "value": "go1.27.2"},
				map[string]any{"name": "cdx:gomod:build:tag", "value": "ts_omit_foo"},
			},
		}},
		"dependencies": []any{map[string]any{"ref": root, "dependsOn": []any{"pkg:golang/std@go1.27.2?type=module"}}},
		"components": []any{map[string]any{
			"name": "std", "version": "go1.27.2",
		}},
	}
}

func TestNormalize(t *testing.T) {
	doc := fixture()
	digest := strings.Repeat("a", 64)
	if err := normalize(doc, digest, "linux", "amd64", "ts_omit_foo"); err != nil {
		t.Fatal(err)
	}
	root := doc["metadata"].(map[string]any)["component"].(map[string]any)
	const want = "v0.0.0-sbom.aaaaaaaaaaaaaaaa"
	if root["version"] != want {
		t.Fatalf("root version = %v, want %s", root["version"], want)
	}
	ref := root["bom-ref"].(string)
	if !strings.Contains(ref, "@"+want+"?") {
		t.Fatalf("root reference version not normalized: %s", ref)
	}
	deps := doc["dependencies"].([]any)[0].(map[string]any)
	if deps["ref"] != ref {
		t.Fatalf("dependency edge is not bound to root: %v vs %s", deps["ref"], ref)
	}
	std := doc["components"].([]any)[0].(map[string]any)
	licenses := std["evidence"].(map[string]any)["licenses"].([]any)
	license := licenses[0].(map[string]any)["license"].(map[string]any)["id"]
	if license != "BSD-3-Clause" {
		t.Fatalf("stdlib license = %v", license)
	}
}

func TestNormalizeRejectsIncompleteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong target", func(m map[string]any) {
			m["metadata"].(map[string]any)["component"].(map[string]any)["properties"].([]any)[1].(map[string]any)["value"] = "windows"
		}},
		{"missing stdlib", func(m map[string]any) { m["components"] = []any{} }},
		{"missing root edge", func(m map[string]any) { m["dependencies"] = []any{} }},
		{"missing release tag", func(m map[string]any) {
			props := m["metadata"].(map[string]any)["component"].(map[string]any)["properties"].([]any)
			m["metadata"].(map[string]any)["component"].(map[string]any)["properties"] = props[:4]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fixture()
			tc.edit(doc)
			if err := normalize(doc, strings.Repeat("b", 64), "linux", "amd64", "ts_omit_foo"); err == nil {
				t.Fatal("expected malformed BOM to be rejected")
			}
		})
	}
}
