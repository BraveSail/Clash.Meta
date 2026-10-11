package log

import (
	"io"
	"os"
	"sync"
	"testing"
	"time"

	logrus "github.com/sirupsen/logrus"
)

// The level is read by every log line and written by every config apply, and
// the two sides run on different goroutines: a hub channel that reports while
// the configuration is being reloaded is enough to hit it. The race detector
// is the assertion here - a bare variable passes this test silently only when
// the scheduling never interleaves.
func TestLevelAccessIsRaceFree(t *testing.T) {
	logrus.SetOutput(io.Discard)
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	defer SetLevel(INFO)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				SetLevel(DEBUG)
				SetLevel(SILENT)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				Debugln("level race probe")
				_ = Level()
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// A write that happens after the readers stop must be visible to the next
	// read: this is the atomicity half, which the race detector cannot see on
	// its own.
	SetLevel(INFO)
	if got := Level(); got != INFO {
		t.Errorf("level = %v after the writers stopped, want %v", got, INFO)
	}
}
