package jwt_test

import (
	jwt "github.com/kernle32dll/jwtcache-go"
	jwtx "github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"context"
	"testing"
	"time"
)

// Tests that the Name option correctly applies.
func Test_Option_Name(t *testing.T) {
	// given
	option := jwt.Name("bar")
	options := &jwt.Config{Name: "foo"}

	// when
	option(options)

	// then
	if options.Name != "bar" {
		t.Errorf("name not correctly applied, got %s", options.Name)
	}
}

// Tests that the Logger option correctly applies.
func Test_Option_Logger(t *testing.T) {
	// given
	oldLogger, oldLoggerHook := test.NewNullLogger()
	newLogger, newLoggerHook := test.NewNullLogger()
	newLogger.Level = logrus.DebugLevel

	option := jwt.Logger(newLogger)
	options := &jwt.Config{Logger: oldLogger}

	// when
	option(options)
	options.Logger.Infof("foo %s", "bar")
	options.Logger.Debugf("kaese %s", "broed")

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
	option := jwt.Headroom(time.Second)
	options := &jwt.Config{Headroom: time.Hour}

	// when
	option(options)

	// then
	if options.Headroom != time.Second {
		t.Errorf("headroom not correctly applied, got %s", options.Headroom)
	}
}

// Tests that the TokenFunction option correctly applies.
func Test_Option_TokenFunction(t *testing.T) {
	// given
	option := jwt.TokenFunction(func(ctx context.Context) (s string, e error) {
		return "some-token", nil
	})

	options := &jwt.Config{TokenFunc: func(ctx context.Context) (s string, e error) {
		return "", jwt.ErrNotImplemented
	}}

	// when
	option(options)

	// then
	if token, err := options.TokenFunc(context.Background()); token != "some-token" || err != nil {
		t.Errorf("token function not correctly applied, got %s ; %s", token, err)
	}
}

// Tests that the ParseOptions option correctly applies.
func Test_Option_ParseOptions(t *testing.T) {
	// given
	newOption := jwtx.WithIssuer("issuer")
	option := jwt.ParseOptions(newOption)
	options := &jwt.Config{ParseOptions: []jwtx.ParseOption{
		jwtx.WithAudience("audience"),
	}}

	// when
	option(options)

	// then
	if len(options.ParseOptions) != 1 || options.ParseOptions[0] != newOption {
		t.Errorf("parse options not correctly applied, got %s", options.ParseOptions)
	}
}

// Tests that the RejectUnparsable option correctly applies.
func Test_Option_RejectUnparsable(t *testing.T) {
	// given
	option := jwt.RejectUnparsable(true)
	options := &jwt.Config{RejectUnparsable: false}

	// when
	option(options)

	// then
	if !options.RejectUnparsable {
		t.Errorf("reject unparsable not correctly applied, got %t", options.RejectUnparsable)
	}
}
