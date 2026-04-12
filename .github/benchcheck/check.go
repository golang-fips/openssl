package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/perf/benchfmt"
	"golang.org/x/perf/benchmath"
)

type benchKey struct {
	Name string
	Unit string
}

type config struct {
	TimeThreshold float64 // minimum sec/op regression percentage
	MinTime       float64 // minimum base time in seconds
	Alpha         float64 // significance level
}

type regression struct {
	Name      string
	Unit      string
	PctChange float64
	PValue    float64
	BaseVal   float64
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	timeThreshold := fs.Float64("time-threshold", 5, "minimum sec/op regression percentage to flag")
	minTime := fs.Duration("min-time", time.Microsecond, "minimum base time for sec/op checks")
	alpha := fs.Float64("alpha", 0.05, "significance level for statistical tests")
	regressionsOut := fs.String("o-regressions", "regressions.txt", "output file for regression details")
	failuresOut := fs.String("o-failures", "failures.txt", "output file for test failure details")
	statusOut := fs.String("o-status", "status.json", "output file for machine-readable status (JSON)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: benchcheck check [flags] base.txt head.txt

Compare base and head benchmark results, detect regressions and test failures.

Writes the following output files (paths configurable via flags):
  regressions.txt  One-line summary per detected regression.
  failures.txt     Extracted build errors, test failures, and crash traces.
  status.json      Machine-readable JSON status for the report subcommand.

Exits 0 if no issues are found, 1 if regressions or failures are detected.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}

	cfg := config{
		TimeThreshold: *timeThreshold,
		MinTime:       minTime.Seconds(),
		Alpha:         *alpha,
	}

	basePath, headPath := fs.Arg(0), fs.Arg(1)

	// Extract test failures from both files.
	var failureLines []string
	var err error
	if failureLines, err = appendFailuresFromFile(failureLines, basePath, "base: "); err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", basePath, err)
	}
	if failureLines, err = appendFailuresFromFile(failureLines, headPath, "head: "); err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", headPath, err)
	}
	hasFailures := len(failureLines) > 0

	// Parse benchmarks and check regressions.
	baseValues := parseBenchmarksFromFile(basePath)
	headValues := parseBenchmarksFromFile(headPath)
	regressions := checkRegressions(baseValues, headValues, cfg)
	hasRegressions := len(regressions) > 0

	// Sort regressions by percentage descending.
	sort.Slice(regressions, func(i, j int) bool {
		return regressions[i].PctChange > regressions[j].PctChange
	})

	// Write regressions.txt.
	var regressionLines []string
	for _, r := range regressions {
		if isAllocUnit(r.Unit) {
			regressionLines = append(regressionLines, fmt.Sprintf("alloc regression: %s [%s] +%.2f%% (p=%.3f)", r.Name, r.Unit, r.PctChange, r.PValue))
		} else {
			regressionLines = append(regressionLines, fmt.Sprintf("time regression: %s +%.2f%% (p=%.3f, base=%.2g sec)", r.Name, r.PctChange, r.PValue, r.BaseVal))
		}
	}
	writeLines(*regressionsOut, regressionLines)
	writeLines(*failuresOut, failureLines)

	// Write status.json.
	writeStatus(*statusOut, hasRegressions, hasFailures)

	// Print summary with GitHub Actions annotations.
	if hasRegressions {
		fmt.Println("::error::Benchmark regression detected — see benchstat output above for details.")
		fmt.Println()
		fmt.Println("=== Regressions ===")
		for _, line := range regressionLines {
			fmt.Println(line)
		}
	}
	if hasFailures {
		fmt.Println("::error::Test failure detected — see the 'Run benchmarks' steps for details.")
		fmt.Println()
		fmt.Println("=== Test failures ===")
		for _, line := range failureLines {
			fmt.Println(line)
		}
	}
	if !hasRegressions && !hasFailures {
		fmt.Println("No benchmark regressions or test failures detected.")
	}
	if hasRegressions || hasFailures {
		os.Exit(1)
	}
}

func appendFailuresFromFile(lines []string, path, prefix string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return lines, err
	}
	defer f.Close()
	result, err := extractFailures(f, prefix)
	return append(lines, result...), err
}

// extractFailures parses go test output and returns lines related to
// build errors, test failures, and crash traces.
func extractFailures(r io.Reader, prefix string) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	inCrash := false
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "# "):
			lines = append(lines, prefix+line)
		case strings.HasPrefix(line, "--- FAIL"):
			lines = append(lines, prefix+line)
		case strings.HasPrefix(line, "FAIL\t"):
			lines = append(lines, prefix+line)
		case !inCrash && isCrashLine(line):
			inCrash = true
			lines = append(lines, prefix+line)
		case inCrash && line == "":
			inCrash = false
			lines = append(lines, "")
		case inCrash:
			lines = append(lines, prefix+line)
		}
	}
	return lines, scanner.Err()
}

// isCrashLine returns true for signal or panic lines (e.g. "SIGSEGV:", "panic:").
func isCrashLine(line string) bool {
	if strings.HasPrefix(line, "panic:") {
		return true
	}
	if !strings.HasPrefix(line, "SIG") {
		return false
	}
	// Match SIG followed by uppercase letters then ':'.
	i := 3
	for i < len(line) && line[i] >= 'A' && line[i] <= 'Z' {
		i++
	}
	return i > 3 && i < len(line) && line[i] == ':'
}

func parseBenchmarksFromFile(path string) map[benchKey][]float64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseBenchmarks(f, path)
}

func parseBenchmarks(r io.Reader, name string) map[benchKey][]float64 {
	result := make(map[benchKey][]float64)
	reader := benchfmt.NewReader(r, name)
	for reader.Scan() {
		rec := reader.Result()
		res, ok := rec.(*benchfmt.Result)
		if !ok {
			continue
		}
		benchName := res.Name.String()
		for _, v := range res.Values {
			key := benchKey{Name: benchName, Unit: v.Unit}
			result[key] = append(result[key], v.Value)
		}
	}
	return result
}

func checkRegressions(base, head map[benchKey][]float64, cfg config) []regression {
	thresholds := &benchmath.Thresholds{CompareAlpha: cfg.Alpha}
	var regressions []regression

	for key, baseVals := range base {
		headVals, ok := head[key]
		if !ok {
			continue
		}

		baseSample := benchmath.NewSample(baseVals, thresholds)
		headSample := benchmath.NewSample(headVals, thresholds)

		cmp := benchmath.AssumeNothing.Compare(baseSample, headSample)
		if cmp.P >= cmp.Alpha {
			continue // not statistically significant
		}

		baseSummary := benchmath.AssumeNothing.Summary(baseSample, 0.95)
		headSummary := benchmath.AssumeNothing.Summary(headSample, 0.95)

		if headSummary.Center <= baseSummary.Center {
			continue // improvement or same
		}

		if baseSummary.Center == 0 {
			// Base is zero; only flag allocation units (sec/op can't be 0 meaningfully).
			if isAllocUnit(key.Unit) {
				regressions = append(regressions, regression{
					Name:      key.Name,
					Unit:      key.Unit,
					PctChange: 100, // 0 → non-zero
					PValue:    cmp.P,
				})
			}
			continue
		}

		pctChange := (headSummary.Center - baseSummary.Center) / baseSummary.Center * 100

		switch {
		case isAllocUnit(key.Unit):
			regressions = append(regressions, regression{
				Name:      key.Name,
				Unit:      key.Unit,
				PctChange: pctChange,
				PValue:    cmp.P,
			})
		case key.Unit == "sec/op":
			if baseSummary.Center >= cfg.MinTime && pctChange >= cfg.TimeThreshold {
				regressions = append(regressions, regression{
					Name:      key.Name,
					Unit:      key.Unit,
					PctChange: pctChange,
					PValue:    cmp.P,
					BaseVal:   baseSummary.Center,
				})
			}
		}
	}

	return regressions
}

func isAllocUnit(unit string) bool {
	return unit == "B/op" || unit == "allocs/op"
}

func writeLines(path string, lines []string) {
	data := []byte(strings.Join(lines, "\n") + "\n")
	if len(lines) == 0 {
		data = nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", path, err)
	}
}

// Status is the machine-readable status written by check and read by report.
type Status struct {
	Regression     bool `json:"regression"`
	TestFailures   bool `json:"test_failures"`
	BenchmarkError bool `json:"benchmark_error"`
}

func writeStatus(path string, regression, failures bool) {
	s := Status{Regression: regression, TestFailures: failures}
	data, err := json.Marshal(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshaling status: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", path, err)
	}
}
