package resolver

import (
	"sync"
	"testing"
	"time"
)

// DisableIPv6 is written by every configuration apply and read by every
// lookup, on different goroutines: the hub channel resolving a name while the
// configuration is reloaded is enough to interleave them. The race detector
// is the real assertion - a bare bool passes this silently only when the
// scheduling never lines the two up.
func TestDisableIPv6AccessIsRaceFree(t *testing.T) {
	previous := DisableIPv6()
	t.Cleanup(func() { SetDisableIPv6(previous) })

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: what a configuration apply does.
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
				SetDisableIPv6(true)
				SetDisableIPv6(false)
			}
		}()
	}
	// Readers: the read every lookup path performs.
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
				_ = DisableIPv6()
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// A write after the readers stop must be visible to the next read: the
	// atomicity half, which the race detector cannot see by itself.
	SetDisableIPv6(false)
	if DisableIPv6() {
		t.Error("DisableIPv6() = true after a store of false")
	}
}
