// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// sbom regenerates or verifies source-derived CycloneDX SBOMs.
// Run from the repository root: go run ./tool/sbom {generate|check}.
// Requires Go 1.27.2 and a separately verified cyclonedx-gomod v1.12.0.
// This helper uses only the Go standard library.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

var targets = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "arm"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "generate" && os.Args[1] != "check") {
		log.Fatal("usage: go run ./tool/sbom {generate|check}")
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func command(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected JSON object, got %T", v)
	}
	return m, nil
}

func fingerprint(source string) (string, error) {
	names, err := command(source, nil, "git", "ls-files", "--",
		"*.go", "go.mod", "go.sum", "build-tags.txt", ".goreleaser.yaml")
	if err != nil {
		return "", err
	}
	list := strings.Split(strings.TrimSpace(names), "\n")
	sort.Strings(list)
	h := sha256.New()
	for _, name := range list {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", name, len(data))
		if _, err := h.Write(data); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func normalize(data map[string]any, digest, goos, goarch, tags string) error {
	if data["bomFormat"] != "CycloneDX" || data["specVersion"] != "1.6" {
		return errors.New("expected CycloneDX 1.6 JSON")
	}
	meta, err := object(data["metadata"])
	if err != nil {
		return err
	}
	root, err := object(meta["component"])
	if err != nil {
		return err
	}
	old, ok := root["version"].(string)
	if !ok || old == "" {
		return errors.New("missing root module version")
	}
	oldRef, ok := root["bom-ref"].(string)
	if !ok {
		return errors.New("missing root bom-ref")
	}
	oldPurl, ok := root["purl"].(string)
	if !ok {
		return errors.New("missing root purl")
	}
	match := "@" + old + "?"
	if !strings.Contains(oldRef, match) || !strings.Contains(oldPurl, match) {
		return errors.New("root identifiers not tied to module version")
	}
	version := "v0.0.0-sbom." + digest[:16]
	newRef := strings.Replace(oldRef, match, "@"+version+"?", 1)
	root["version"] = version
	root["bom-ref"] = newRef
	root["purl"] = strings.Replace(oldPurl, match, "@"+version+"?", 1)

	props, ok := root["properties"].([]any)
	if !ok {
		return errors.New("missing build properties")
	}
	expected := map[string]string{
		"cdx:gomod:build:env:CGO_ENABLED": "0",
		"cdx:gomod:build:env:GOOS":        goos,
		"cdx:gomod:build:env:GOARCH":      goarch,
		"cdx:gomod:build:env:GOVERSION":   "go1.27.2",
	}
	foundTags := map[string]bool{}
	for _, p := range props {
		o, err := object(p)
		if err != nil {
			return err
		}
		name, _ := o["name"].(string)
		value, _ := o["value"].(string)
		if v, ok := expected[name]; ok {
			if v != value {
				return fmt.Errorf("incorrect %s: %s", name, value)
			}
			delete(expected, name)
		}
		if name == "cdx:gomod:build:tag" {
			foundTags[value] = true
		}
	}
	if len(expected) > 0 || len(foundTags) != len(strings.Split(tags, ",")) {
		return errors.New("missing build attributes or release tags")
	}
	for _, tag := range strings.Split(tags, ",") {
		if !foundTags[tag] {
			return fmt.Errorf("missing tag: %s", tag)
		}
	}
	root["properties"] = append(props, map[string]any{
		"name": "tailcat:source-inputs:sha256", "value": digest,
	})
	deps, ok := data["dependencies"].([]any)
	if !ok {
		return errors.New("missing dependencies")
	}
	roots := 0
	for _, d := range deps {
		edge, err := object(d)
		if err != nil {
			return err
		}
		if edge["ref"] == oldRef {
			edge["ref"] = newRef
			roots++
		}
	}
	if roots != 1 {
		return fmt.Errorf("expected exactly one root dependency edge, got %d", roots)
	}
	components, ok := data["components"].([]any)
	if !ok {
		return errors.New("missing components")
	}
	stdCount := 0
	for _, component := range components {
		c, err := object(component)
		if err != nil {
			return err
		}
		if c["name"] != "std" {
			continue
		}
		stdCount++
		if c["version"] != "go1.27.2" {
			return errors.New("wrong Go standard library version")
		}
		evidence, ok := c["evidence"].(map[string]any)
		if !ok {
			if c["evidence"] != nil {
				return errors.New("malformed stdlib evidence")
			}
			evidence = make(map[string]any)
			c["evidence"] = evidence
		}
		if licenses, _ := evidence["licenses"].([]any); len(licenses) == 0 {
			// Go 1.27.2 source LICENSE is BSD-3-Clause.
			evidence["licenses"] = []any{map[string]any{"license": map[string]any{"id": "BSD-3-Clause"}}}
		}
		stdProps, _ := c["properties"].([]any)
		c["properties"] = append(stdProps, map[string]any{
			"name":  "tailcat:stdlib-license-source",
			"value": "https://go.googlesource.com/go/+/refs/tags/go1.27.2/LICENSE",
		})
	}
	if stdCount != 1 {
		return fmt.Errorf("expected one Go standard-library component, got %d", stdCount)
	}
	return nil
}

func run(mode string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("run from repository root: %w", err)
	}
	version, err := command(root, nil, "cyclonedx-gomod", "version")
	if err != nil || !strings.Contains(version, "Version:\tv1.12.0\n") {
		return fmt.Errorf("require cyclonedx-gomod v1.12.0: %v", err)
	}
	version, err = command(root, nil, "go", "version")
	if err != nil || !strings.Contains(version, "go version go1.27.2 ") {
		return fmt.Errorf("require Go 1.27.2: %s (%v)", version, err)
	}
	head, err := command(root, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "tailcat-sbom-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	source := filepath.Join(temp, "source")
	// No remote access: a full local checkout also supports linked worktrees.
	if _, err := command(root, nil, "git", "clone", "--quiet", "--no-hardlinks", root, source); err != nil {
		return err
	}
	if _, err := command(source, nil, "git", "checkout", "--quiet", "--detach", strings.TrimSpace(head)); err != nil {
		return err
	}
	digest, err := fingerprint(source)
	if err != nil {
		return err
	}
	tagBytes, err := os.ReadFile(filepath.Join(source, "build-tags.txt"))
	if err != nil {
		return err
	}
	tags := strings.TrimSpace(string(tagBytes))
	if tags == "" {
		return errors.New("empty release tags")
	}
	out := filepath.Join(temp, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	for _, target := range targets {
		goos, goarch := target[0], target[1]
		name := fmt.Sprintf("tailcat-%s-%s.cdx.json", goos, goarch)
		output := filepath.Join(out, name)
		env := append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch,
			"GOARM=7", "CGO_ENABLED=0", "GOFLAGS=-tags="+tags)
		if _, err := command(source, env, "cyclonedx-gomod", "app",
			"-main", "cmd/tailcat", "-std", "-noserial", "-notimestamp",
			"-json", "-licenses", "-output", output, "."); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		raw, err := os.ReadFile(output)
		if err != nil {
			return err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		if err := normalize(doc, digest, goos, goarch, tags); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		destination := filepath.Join(root, "sbom", name)
		if mode == "generate" {
			encoded, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(destination, append(encoded, '\n'), 0644); err != nil {
				return err
			}
			fmt.Println("generated", filepath.Join("sbom", name))
		} else {
			saved, err := os.ReadFile(destination)
			if err != nil {
				return err
			}
			var actual any
			if err := json.Unmarshal(saved, &actual); err != nil {
				return err
			}
			if !reflect.DeepEqual(doc, actual) {
				return fmt.Errorf("SBOM stale: %s", name)
			}
			fmt.Println("verified", filepath.Join("sbom", name))
		}
	}
	return nil
}
