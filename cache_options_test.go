package jwt

import (
	"context"
	"testing"
	"time"
)

// loggerMock is a LoggerContract mock, which captures the input.
type loggerMock struct {
	capturedInfoFormat  string
	capturedInfoArgs    []interface{}
	capturedDebugFormat string
	capturedDebugArgs   []interface{}
}

func (logger *loggerMock) Infof(format string, args ...interface{}) {
	logger.capturedInfoFormat = format
	logger.capturedInfoArgs = args
}

func (logger *loggerMock) Debugf(format string, args ...interface{}) {
	logger.capturedDebugFormat = format
	logger.capturedDebugArgs = args

}

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
	oldLogger := &loggerMock{}
	newLogger := &loggerMock{}

	option := Logger(newLogger)
	options := &config{logger: oldLogger}

	// when
	option(options)
	options.logger.Infof("foo", "bar")
	options.logger.Debugf("kaese", "broed")

	// then
	if newLogger.capturedInfoFormat != "foo" || newLogger.capturedInfoArgs[0] != "bar" {
		t.Errorf("logger not correctly applied, got %s ; %s", newLogger.capturedInfoFormat, newLogger.capturedInfoArgs)
	}

	if newLogger.capturedDebugFormat != "kaese" || newLogger.capturedDebugArgs[0] != "broed" {
		t.Errorf("logger not correctly applied, got %s ; %s", newLogger.capturedDebugFormat, newLogger.capturedDebugArgs)
	}

	// ensure old logger sees no usage
	if oldLogger.capturedInfoFormat != "" || len(oldLogger.capturedInfoArgs) > 0 ||
		oldLogger.capturedDebugFormat != "" || len(oldLogger.capturedDebugArgs) > 0 {
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
