package main

import (
	"fmt"
	"strings"
	"testing"
)

// benchLines generates n identical benchmark result lines.
func benchLines(name string, n int, nsPerOp float64, bPerOp, allocsPerOp int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s\t1\t%.1f ns/op\t%d B/op\t%d allocs/op\n",
			name, nsPerOp, bPerOp, allocsPerOp)
	}
	return b.String()
}

func parse(t *testing.T, text string) map[benchKey][]float64 {
	t.Helper()
	return parseBenchmarks(strings.NewReader(text), "test.txt")
}

func defaultCfg() config {
	return config{
		TimeThreshold: 5,
		MinTime:       1e-6, // 1µs
		Alpha:         0.05,
	}
}

func TestNoRegression(t *testing.T) {
	data := benchLines("BenchmarkFoo-8", 10, 5000, 64, 2)
	base := parse(t, data)
	head := parse(t, data)
	regressions := checkRegressions(base, head, defaultCfg())
	if len(regressions) != 0 {
		t.Errorf("expected no regressions, got %d: %+v", len(regressions), regressions)
	}
}

func TestAllocRegression_BPerOp(t *testing.T) {
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 64, 2))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 128, 2))
	regressions := checkRegressions(base, head, defaultCfg())
	found := false
	for _, r := range regressions {
		if r.Unit == "B/op" {
			found = true
		}
	}
	if !found {
		t.Error("expected B/op regression, got none")
	}
}

func TestAllocRegression_AllocsPerOp(t *testing.T) {
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 64, 2))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 64, 4))
	regressions := checkRegressions(base, head, defaultCfg())
	found := false
	for _, r := range regressions {
		if r.Unit == "allocs/op" {
			found = true
		}
	}
	if !found {
		t.Error("expected allocs/op regression, got none")
	}
}

func TestTimeRegression_AboveThreshold(t *testing.T) {
	// 5000 ns = 5µs (above 1µs minimum), 10% regression (above 5% threshold)
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 0, 0))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5500, 0, 0))
	regressions := checkRegressions(base, head, defaultCfg())
	found := false
	for _, r := range regressions {
		if r.Unit == "sec/op" {
			found = true
		}
	}
	if !found {
		t.Error("expected sec/op regression, got none")
	}
}

func TestTimeRegression_BelowMinTime(t *testing.T) {
	// 50 ns (below 1µs minimum) — should NOT flag even with large % increase
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 50, 0, 0))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 100, 0, 0))
	regressions := checkRegressions(base, head, defaultCfg())
	for _, r := range regressions {
		if r.Unit == "sec/op" {
			t.Errorf("unexpected sec/op regression for sub-µs benchmark: %+v", r)
		}
	}
}

func TestTimeRegression_BelowPctThreshold(t *testing.T) {
	// 5000 ns = 5µs, but only 2% regression (below 5% threshold)
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 0, 0))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5100, 0, 0))
	regressions := checkRegressions(base, head, defaultCfg())
	for _, r := range regressions {
		if r.Unit == "sec/op" {
			t.Errorf("unexpected sec/op regression for <5%% change: %+v", r)
		}
	}
}

func TestImprovement_NotFlagged(t *testing.T) {
	// Head is faster — should NOT flag
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 64, 2))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 4000, 32, 1))
	regressions := checkRegressions(base, head, defaultCfg())
	if len(regressions) != 0 {
		t.Errorf("expected no regressions for improvement, got %d: %+v",
			len(regressions), regressions)
	}
}

func TestZeroBaseAlloc(t *testing.T) {
	// Base has 0 B/op, head has non-zero
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 0, 0))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 64, 2))
	regressions := checkRegressions(base, head, defaultCfg())
	allocFound := false
	for _, r := range regressions {
		if isAllocUnit(r.Unit) {
			allocFound = true
		}
	}
	if !allocFound {
		t.Error("expected allocation regression for 0→non-zero, got none")
	}
}

func TestCustomThresholds(t *testing.T) {
	// 10% time threshold — 8% regression should NOT flag
	base := parse(t, benchLines("BenchmarkFoo-8", 10, 5000, 0, 0))
	head := parse(t, benchLines("BenchmarkFoo-8", 10, 5400, 0, 0))
	cfg := config{
		TimeThreshold: 10,
		MinTime:       1e-6,
		Alpha:         0.05,
	}
	regressions := checkRegressions(base, head, cfg)
	for _, r := range regressions {
		if r.Unit == "sec/op" {
			t.Errorf("unexpected sec/op regression with 10%% threshold: %+v", r)
		}
	}
}

func TestParseBenchmarks(t *testing.T) {
	input := "BenchmarkSHA256-8\t1000\t1234 ns/op\t56 B/op\t3 allocs/op\n" +
		"BenchmarkSHA256-8\t1000\t1245 ns/op\t56 B/op\t3 allocs/op\n" +
		"BenchmarkAES-8\t1000\t567 ns/op\t0 B/op\t0 allocs/op\n"
	values := parse(t, input)

	// benchfmt strips the "Benchmark" prefix from names.
	sha256Time := values[benchKey{Name: "SHA256-8", Unit: "sec/op"}]
	if len(sha256Time) != 2 {
		t.Fatalf("expected 2 sec/op values for SHA256, got %d", len(sha256Time))
	}
	// 1234 ns = 1.234e-6 sec
	if sha256Time[0] < 1e-7 || sha256Time[0] > 1e-5 {
		t.Errorf("unexpected sec/op value: %g", sha256Time[0])
	}

	sha256Alloc := values[benchKey{Name: "SHA256-8", Unit: "B/op"}]
	if len(sha256Alloc) != 2 {
		t.Fatalf("expected 2 B/op values for SHA256, got %d", len(sha256Alloc))
	}
}

func TestExtractFailures_BuildErrors(t *testing.T) {
	input := "# runtime/cgo\ncgo-gcc-prolog:3:20: error: call to undeclared function\nFAIL\tgithub.com/example [build failed]\n"
	lines, err := extractFailures(strings.NewReader(input), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "# ") {
		t.Errorf("expected build error line, got: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "FAIL\t") {
		t.Errorf("expected FAIL line, got: %s", lines[1])
	}
}

func TestExtractFailures_TestFailures(t *testing.T) {
	input := "--- FAIL: TestFoo (0.01s)\n    foo_test.go:42: expected 1, got 2\nFAIL\tgithub.com/example\t0.123s\n"
	lines, err := extractFailures(strings.NewReader(input), "pfx: ")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "pfx: --- FAIL: TestFoo (0.01s)" {
		t.Errorf("unexpected line: %s", lines[0])
	}
	if lines[1] != "pfx: FAIL\tgithub.com/example\t0.123s" {
		t.Errorf("unexpected line: %s", lines[1])
	}
}

func TestExtractFailures_CrashTrace(t *testing.T) {
	input := "SIGSEGV: segmentation violation\nPC=0x1234\ngoroutine 1 [running]:\nmain.foo()\n\tfile.go:10\n\ngoroutine 2 [sleep]:\ntime.Sleep()\n"
	lines, err := extractFailures(strings.NewReader(input), "")
	if err != nil {
		t.Fatal(err)
	}
	// Should capture lines up to and including the blank line, not goroutine 2.
	found := false
	for _, l := range lines {
		if strings.Contains(l, "goroutine 2") {
			t.Error("should not capture second goroutine")
		}
		if strings.Contains(l, "SIGSEGV") {
			found = true
		}
	}
	if !found {
		t.Error("expected SIGSEGV line")
	}
}

func TestExtractFailures_Panic(t *testing.T) {
	input := "panic: runtime error: index out of range\ngoroutine 1 [running]:\nmain.foo()\n\n"
	lines, err := extractFailures(strings.NewReader(input), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("expected panic lines")
	}
	if !strings.HasPrefix(lines[0], "panic:") {
		t.Errorf("expected panic line, got: %s", lines[0])
	}
}

func TestExtractFailures_NoFailures(t *testing.T) {
	input := "BenchmarkFoo-8\t1000\t1234 ns/op\t56 B/op\t3 allocs/op\nok\tgithub.com/example\t1.234s\n"
	lines, err := extractFailures(strings.NewReader(input), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Errorf("expected no failures, got %d: %v", len(lines), lines)
	}
}

func TestIsCrashLine(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"SIGSEGV: segmentation violation", true},
		{"SIGABRT: abort", true},
		{"panic: runtime error", true},
		{"SIGTERM", false},           // no colon
		{"SIG: bad", false},          // no uppercase letters between SIG and :
		{"SIGNATURE: foo", true},     // SIG + uppercase + colon
		{"something else", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isCrashLine(tt.line); got != tt.want {
			t.Errorf("isCrashLine(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
