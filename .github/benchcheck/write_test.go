package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteLines_EmptyPathSkips(t *testing.T) {
	if err := writeLines("", []string{"hello"}); err != nil {
		t.Fatalf("expected nil error for empty path, got %v", err)
	}
}

func TestWriteLines_WritesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writeLines(path, []string{"a", "b"}); err != nil {
		t.Fatalf("writeLines: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "a\nb\n" {
		t.Errorf("unexpected contents: %q", got)
	}
}

func TestWriteLines_EmptyLinesWritesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writeLines(path, nil); err != nil {
		t.Fatalf("writeLines: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
}

func TestWriteFile_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "out.txt")
	if err := writeFile(path, []byte("data")); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("unexpected contents: %q", got)
	}
}

func TestWriteStatus_EmptyPathSkips(t *testing.T) {
	if err := writeStatus("", Status{Regression: true}); err != nil {
		t.Fatalf("expected nil error for empty path, got %v", err)
	}
}

func TestWriteStatus_WritesAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "status.json")
	want := Status{Regression: true, TestFailures: false, BenchmarkError: true}
	if err := writeStatus(path, want); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got Status
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Errorf("status mismatch: got %+v, want %+v", got, want)
	}
}

func TestStatus_Failed(t *testing.T) {
	cases := []struct {
		s    Status
		want bool
	}{
		{Status{}, false},
		{Status{Regression: true}, true},
		{Status{TestFailures: true}, true},
		{Status{BenchmarkError: true}, true},
	}
	for _, tc := range cases {
		if got := tc.s.Failed(); got != tc.want {
			t.Errorf("Status%+v.Failed() = %v, want %v", tc.s, got, tc.want)
		}
	}
}
