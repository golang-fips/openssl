// Package badversion contains negative fixtures: every gated call inside
// a 3+ branch lacks a //versionguardcheck:ignore marker and must be flagged.
//
// Each "// want:" comment documents the violation expected on the
// following line; versionguardcheck_test.go uses these to assert that the
// analyzer's output matches exactly.
package badversion

func major() int                        { return 3 }
func minor() int                        { return 0 }
func patch() int                        { return 0 }
func versionAtOrAbove(a, b, c int) bool { return true }
func checkMajorVersion(expected ...int) {}

func threePlusBranch() {
	switch major() {
	case 3, 4:
		// want: minor
		_ = minor()
		// want: versionAtOrAbove
		_ = versionAtOrAbove(3, 2, 0)
		// want: checkMajorVersion
		checkMajorVersion(3, 4)
	}
}

func defaultBranch() {
	switch major() {
	case 1:
		// not flagged
		_ = minor()
	default:
		// want: patch
		_ = patch()
	}
}

// inlineMarker: marker on the same line as the call is rejected. The
// marker must be on the line immediately above.
func inlineMarker() {
	switch major() {
	case 3, 4:
		// want: minor
		_ = minor() //versionguardcheck:ignore inline marker is not accepted
	}
}

// emptyReasonMarker: //versionguardcheck:ignore with no reason is rejected.
func emptyReasonMarker() {
	switch major() {
	case 3, 4:
		//versionguardcheck:ignore
		// want: minor
		_ = minor()
		//versionguardcheck:ignore
		// want: patch
		_ = patch()
	}
}

// noWordBoundaryMarker: the prefix must end at a word boundary;
// //versionguardcheck:ignoresomething is not a marker.
func noWordBoundaryMarker() {
	switch major() {
	case 3, 4:
		//versionguardcheck:ignoreMissingSpace this is not a valid marker
		// want: minor
		_ = minor()
	}
}
