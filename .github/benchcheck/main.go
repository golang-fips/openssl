// benchcheck reads two Go benchmark result files and detects regressions.
//
// Usage: benchcheck [flags] base.txt head.txt
//
// It prints "true" to stdout if any regressions are found, "false" otherwise.
// Regression details are printed to stderr.
//
// Regression rules:
//   - B/op or allocs/op: any statistically significant increase.
//   - sec/op: statistically significant increase >= threshold,
//     but only for benchmarks whose base time >= min-time.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/perf/benchfmt"
	"golang.org/x/perf/benchmath"
)

var (
	timeThreshold = flag.Float64("time-threshold", 5, "minimum sec/op regression percentage to flag")
	minTime       = flag.Duration("min-time", time.Microsecond, "minimum base time for sec/op checks")
	alpha         = flag.Float64("alpha", 0.05, "significance level for statistical tests")
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

func main() {
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "usage: benchcheck [flags] base.txt head.txt\n")
		os.Exit(2)
	}

	cfg := config{
		TimeThreshold: *timeThreshold,
		MinTime:       minTime.Seconds(),
		Alpha:         *alpha,
	}

	baseFile, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading base: %v\n", err)
		os.Exit(1)
	}
	defer baseFile.Close()
	baseValues := parseBenchmarks(baseFile, flag.Arg(0))

	headFile, err := os.Open(flag.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading head: %v\n", err)
		os.Exit(1)
	}
	defer headFile.Close()
	headValues := parseBenchmarks(headFile, flag.Arg(1))

	regressions := checkRegressions(baseValues, headValues, cfg)
	for _, r := range regressions {
		if isAllocUnit(r.Unit) {
			fmt.Fprintf(os.Stderr, "alloc regression: %s [%s] +%.2f%% (p=%.3f)\n",
				r.Name, r.Unit, r.PctChange, r.PValue)
		} else {
			fmt.Fprintf(os.Stderr, "time regression: %s +%.2f%% (p=%.3f, base=%.2g sec)\n",
				r.Name, r.PctChange, r.PValue, r.BaseVal)
		}
	}

	if len(regressions) > 0 {
		fmt.Println("true")
	} else {
		fmt.Println("false")
	}
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
