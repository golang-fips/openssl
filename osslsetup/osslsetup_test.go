//go:build !cmd_go_bootstrap

package osslsetup

import "testing"

func TestGodebugAllowUntested(t *testing.T) {
	tests := []struct {
		name    string
		godebug string
		want    bool
	}{
		{"empty", "", false},
		{"unrelated", "http2debug=1,gctrace=1", false},
		{"only setting", "ms_opensslallowuntested=1", true},
		{"first of many", "ms_opensslallowuntested=1,gctrace=1", true},
		{"middle of many", "http2debug=1,ms_opensslallowuntested=1,gctrace=1", true},
		{"last of many", "http2debug=1,ms_opensslallowuntested=1", true},
		{"value zero", "ms_opensslallowuntested=0", false},
		{"no value", "ms_opensslallowuntested", false},
		// internal/godebug treats spaces as part of the entry, so leading
		// or trailing whitespace makes the setting unrecognized. Match it.
		{"leading space", " ms_opensslallowuntested=1", false},
		{"trailing space", "ms_opensslallowuntested=1 ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := godebugAllowUntested(tt.godebug); got != tt.want {
				t.Errorf("godebugAllowUntested(%q) = %v, want %v",
					tt.godebug, got, tt.want)
			}
		})
	}
}

func TestTestedMajorsAreSorted(t *testing.T) {
	// Sorted-ascending isn't load-bearing, just keeps the list readable.
	for i := 1; i < len(testedMajors); i++ {
		if testedMajors[i] <= testedMajors[i-1] {
			t.Fatalf("testedMajors not strictly ascending: %v", testedMajors)
		}
	}
}
