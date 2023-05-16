package zerolog

import "github.com/rs/zerolog"

// LoggerBridge is a bridge implementation for using a zerolog
// logger with a jwt.LoggerContract.
type LoggerBridge struct {
	Logger zerolog.Logger
}

func (z LoggerBridge) Infof(format string, args ...interface{}) {
	z.Logger.Info().Msgf(format, args...)
}

func (z LoggerBridge) Debugf(format string, args ...interface{}) {
	z.Logger.Debug().Msgf(format, args...)
}
