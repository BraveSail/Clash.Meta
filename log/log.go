package log

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	// level is read by every log line and written by every configuration
	// apply, on different goroutines: a hub channel reporting while the
	// configuration is reloaded interleaves the two. It is atomic because a
	// concurrent read and write of it is a data race, which the runtime
	// reports - and can tear - no matter how briefly the window lasts.
	level atomic.Int32
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
	level.Store(int32(INFO))
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	event := newLog(INFO, format, v...)
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	event := newLog(WARNING, format, v...)
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	event := newLog(ERROR, format, v...)
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	level.Store(int32(newLevel))
}

func print(data Event) {
	if data.LogLevel < LogLevel(level.Load()) {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
