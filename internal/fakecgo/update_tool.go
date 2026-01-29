//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	lockFile = "fakecgo.lock"
	repoAPI  = "https://api.github.com/repos/ebitengine/purego/commits/main"
	baseURL  = "https://raw.githubusercontent.com/ebitengine/purego"
)

type lockData struct {
	CommitHash string `json:"commit_hash"`
}

type githubCommit struct {
	SHA string `json:"sha"`
}

var filesToSkip = makeSet(
	"update_tool.go",
	"generate.go",
	"fakecgo.lock",
	// TODO remove once https://github.com/ebitengine/purego/pull/344 is merged
	"linux.go",
	"ztrampolines_linux_386.s",
	"ztrampolines_linux_amd64.s",
	"ztrampolines_linux_arm.s",
	"ztrampolines_linux_arm64.s",
	"ztrampolines_linux_riscv64.s",
	"zsymbols_linux.go",
	"fakecgo.go",
	// TODO remove once https://github.com/ebitengine/purego/pull/403 is merged
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
	// Determine commit hash to use
	commitHash, err := getCommitHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining commit hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Using commit: %s\n", commitHash)

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
		if err := updateFile(name, commitHash); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	fmt.Println("Done.")
}

// getCommitHash returns the commit hash to use for fetching files.
// If the lock file exists, it reads and returns the locked commit hash.
// If the lock file doesn't exist, it fetches the latest commit from main,
// writes it to the lock file, and returns it.
func getCommitHash() (string, error) {
	// Try to read existing lock file
	data, err := os.ReadFile(lockFile)
	if err == nil {
		var lock lockData
		if err := json.Unmarshal(data, &lock); err != nil {
			return "", fmt.Errorf("failed to parse lock file: %w", err)
		}
		if lock.CommitHash != "" {
			return lock.CommitHash, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read lock file: %w", err)
	}

	// Lock file doesn't exist or is invalid, fetch latest commit from main
	fmt.Println("Lock file not found, fetching latest commit from main...")
	resp, err := http.Get(repoAPI)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest commit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status from GitHub API: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var commit githubCommit
	if err := json.Unmarshal(body, &commit); err != nil {
		return "", fmt.Errorf("failed to parse commit response: %w", err)
	}

	if commit.SHA == "" {
		return "", fmt.Errorf("no commit SHA found in response")
	}

	// Write lock file
	lock := lockData{CommitHash: commit.SHA}
	lockJSON, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal lock data: %w", err)
	}

	// Append newline to follow text file conventions
	lockJSON = append(lockJSON, '\n')

	if err := os.WriteFile(lockFile, lockJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write lock file: %w", err)
	}

	fmt.Printf("Created lock file with commit: %s\n", commit.SHA)
	return commit.SHA, nil
}

func updateFile(name, commitHash string) error {
	url := fmt.Sprintf("%s/%s/internal/fakecgo/%s", baseURL, commitHash, name)
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
