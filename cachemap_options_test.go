package jwt

import (
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"context"
	"testing"
	"time"
)

// Tests that the MapName option correctly applies.
func Test_MapOption_Name(t *testing.T) {
	// given
	option := MapName("bar")
	options := &mapConfig{name: "foo"}

	// when
	option(options)

	// then
	if options.name != "bar" {
		t.Errorf("name not correctly applied, got %s", options.name)
	}
}

// Tests that the MapLogger option correctly applies.
func Test_MapOption_Logger(t *testing.T) {
	// given
	oldLogger, oldLoggerHook := test.NewNullLogger()
	newLogger, newLoggerHook := test.NewNullLogger()
	newLogger.Level = logrus.DebugLevel

	option := MapLogger(newLogger)
	options := &mapConfig{logger: oldLogger}

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

// Tests that the MapHeadroom option correctly applies.
func Test_MapOption_Headroom(t *testing.T) {
	// given
	option := MapHeadroom(time.Second)
	options := &mapConfig{headroom: time.Hour}

	// when
	option(options)

	// then
	if options.headroom != time.Second {
		t.Errorf("headroom not correctly applied, got %s", options.headroom)
	}
}

// Tests that the MapTokenFunction option correctly applies.
func Test_MapOption_TokenFunction(t *testing.T) {
	// given
	option := MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
		return "some-token", nil
	})

	options := &mapConfig{tokenFunc: func(ctx context.Context, key string) (s string, e error) {
		return "", ErrNotImplemented
	}}

	// when
	option(options)

	// then
	if token, err := options.tokenFunc(context.Background(), "some-key"); token != "some-token" || err != nil {
		t.Errorf("token function not correctly applied, got %s ; %s", token, err)
	}
}

// Tests that the MapParseOptions option correctly applies.
func Test_MapOption_ParseOptions(t *testing.T) {
	// given
	newOption := jwt.WithIssuer("issuer")
	option := MapParseOptions(newOption)
	options := &mapConfig{parseOptions: []jwt.Option{
		jwt.WithAudience("audience"),
	}}

	// when
	option(options)

	// then
	if len(options.parseOptions) != 1 || options.parseOptions[0] != newOption {
		t.Errorf("parse options not correctly applied, got %s", options.parseOptions)
	}
}

// Tests that the MapRejectUnparsable option correctly applies.
func Test_MapOption_RejectUnparsable(t *testing.T) {
	// given
	option := MapRejectUnparsable(true)
	options := &mapConfig{rejectUnparsable: false}

	// when
	option(options)

	// then
	if !options.rejectUnparsable {
		t.Errorf("reject unparsable not correctly applied, got %t", options.rejectUnparsable)
	}
}
