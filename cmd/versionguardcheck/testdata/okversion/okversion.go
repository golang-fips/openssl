// Package okversion contains positive fixtures: every gated call in a 3+
// branch is justified by a //versionguardcheck:ignore marker on the line
// above, or is in a 1.x branch (and therefore exempt), or is outside any
// `switch major()` (and therefore not analyzed).
package okversion

func major() int                        { return 3 }
func minor() int                        { return 0 }
func patch() int                        { return 0 }
func versionAtOrAbove(a, b, c int) bool { return true }
func checkMajorVersion(expected ...int) {}

func oneBranchOnly() {
	switch major() {
	case 1:
		// 1.x branch is exempt: gated calls here are not flagged.
		_ = minor()
		_ = patch()
		_ = versionAtOrAbove(1, 1, 1)
		checkMajorVersion(1)
	}
}

func markedThreePlus() {
	switch major() {
	case 3, 4:
		//versionguardcheck:ignore workaround for openssl/openssl#17811
		if minor() == 0 && patch() <= 2 {
			_ = 1
		}
		//versionguardcheck:ignore require 3.2+ for foo
		if versionAtOrAbove(3, 2, 0) {
			_ = 2
		}
	}
}

func outsideAnySwitchIsExempt() {
	// Calls outside `switch major()` are not analyzed by versionguardcheck.
	// The migration PRs are responsible for either moving these into a
	// proper switch or replacing them with capability/algorithm probes.
	if versionAtOrAbove(3, 5, 0) {
		_ = minor()
	}
}

func majorAlwaysExempt() {
	// major() is exempt because the outer `switch major()` between 1.x
	// and 3+ is the deliberate top-level dispatch.
	switch major() {
	case 3, 4:
		if major() == 3 {
			_ = 1
		}
	}
}
