package openssl

import (
	"runtime"
	"testing"
	"time"
)

func init() {
	// The runtime parks the "main" thread of the process on Linux rather of
	// terminating it. Lock the main thread to the initial goroutine to ensure
	// that the test goroutines will always be scheduled onto non-main threads
	// that can be consistently made to terminate on demand.
	runtime.LockOSThread()
}

func TestThreadCleanup(t *testing.T) {
	if vMajor > 1 || vMinor > 0 {
		t.Skip("explicit thread cleanup is only needed for OpenSSL 1.0.x")
	}

	before := opensslThreadsCleanedUp()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The thread this goroutine is running on will be terminated by the
		// runtime when the goroutine exits.
		runtime.LockOSThread()
		// Checking for errors has the side effect of initializing
		// the thread-local OpenSSL error queue.
		_ = newOpenSSLError("")
	}()
	<-done
	time.Sleep(100 * time.Millisecond) // Give some time for the thread to terminate.
	after := opensslThreadsCleanedUp()

	if n := after - before; n != 1 {
		t.Errorf("expected thread cleanup to have run once, but it ran %d times", n)
	}
}
