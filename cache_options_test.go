package jwt

import (
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"context"
	"testing"
	"time"
)

// Tests that the Name option correctly applies.
func Test_Option_Name(t *testing.T) {
	// given
	option := Name("bar")
	options := &config{name: "foo"}

	// when
	option(options)

	// then
	if options.name != "bar" {
		t.Errorf("name not correctly applied, got %s", options.name)
	}
}

// Tests that the Logger option correctly applies.
func Test_Option_Logger(t *testing.T) {
	// given
	oldLogger, oldLoggerHook := test.NewNullLogger()
	newLogger, newLoggerHook := test.NewNullLogger()
	newLogger.Level = logrus.DebugLevel

	option := Logger(newLogger)
	options := &config{logger: oldLogger}

	// when
	option(options)
	options.logger.Infof("foo %s", "bar")
	options.logger.Debugf("kaese %s", "broed")

	// then
	if lastEntry := newLoggerHook.Entries[0]; lastEntry.Message != "foo bar" || lastEntry.Level != logrus.InfoLevel {
		t.Errorf("logger not correctly applied. Expected %q@%s got %q@%s", "foo bar", logrus.InfoLevel, lastEntry.Message, lastEntry.Level)
	}

	if lastEntry := newLoggerHook.Entries[1]; lastEntry.Message != "kaese broed" || lastEntry.Level != logrus.DebugLevel {
		t.Errorf("logger not correctly applied. Expected %q@%s got %q@%s", "kaese broed", logrus.DebugLevel, lastEntry.Message, lastEntry.Level)
	}

	// ensure old logger sees no usage
	if len(oldLoggerHook.AllEntries()) > 0 {
		t.Errorf("logger not correctly applied, old logger was used at least once")
	}
}

// Tests that the Headroom option correctly applies.
func Test_Option_Headroom(t *testing.T) {
	// given
	option := Headroom(time.Second)
	options := &config{headroom: time.Hour}

	// when
	option(options)

	// then
	if options.headroom != time.Second {
		t.Errorf("headroom not correctly applied, got %s", options.headroom)
	}
}

// Tests that the TokenFunction option correctly applies.
func Test_Option_TokenFunction(t *testing.T) {
	// given
	option := TokenFunction(func(ctx context.Context) (s string, e error) {
		return "some-token", nil
	})

	options := &config{tokenFunc: func(ctx context.Context) (s string, e error) {
		return "", ErrNotImplemented
	}}

	// when
	option(options)

	// then
	if token, err := options.tokenFunc(context.Background()); token != "some-token" || err != nil {
		t.Errorf("token function not correctly applied, got %s ; %s", token, err)
	}
}
