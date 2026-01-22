//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const baseURL = "https://raw.githubusercontent.com/ebitengine/purego/main/internal/fakecgo"

var filesToSkip = makeSet(
	"update_tool.go",
	"generate.go",
	// TODO remove once https://github.com/ebitengine/purego/pull/344 is merged
	"linux.go",
	"ztrampolines_linux_386.s",
	"ztrampolines_linux_amd64.s",
	"ztrampolines_linux_arm.s",
	"ztrampolines_linux_arm64.s",
	"ztrampolines_linux_riscv64.s",
	"zsymbols_linux.go",
	"fakecgo.go",
	// TODO remove once https://github.com/ebitengine/purego/pull/391 is merged
	"go_util.go",
	"asm_arm.s",
	"trampolines_arm.s",
	// TODO remove once 386 support is added to purego
	"asm_386.s",
	"trampolines_386.s",
)

func makeSet(items ...string) map[string]bool {
	s := make(map[string]bool)
	for _, item := range items {
		s[item] = true
	}
	return s
}

func main() {
	files, err := os.ReadDir(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading directory: %v\n", err)
		os.Exit(1)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()

		if filesToSkip[name] {
			continue
		}

		fmt.Printf("Updating %s...\n", name)
		if err := updateFile(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	fmt.Println("Done.")
}

func updateFile(name string) error {
	url := fmt.Sprintf("%s/%s", baseURL, name)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	if !strings.Contains(name, "darwin") && !strings.Contains(name, "linux") {
		content = modifyBuildTags(content)
	}

	// Preserve file permissions if possible, but 0644 is standard for source files.
	// The original script uses curl -o which overwrites.
	if err := os.WriteFile(name, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func modifyBuildTags(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		if bytes.HasPrefix(line, []byte("//go:build")) {
			lines[i] = []byte("//go:build !cgo && (darwin || linux)")
		}
	}
	return bytes.Join(lines, []byte("\n"))
}
