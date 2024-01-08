package logger

const (
	infoLogLevelPrefix  = " [INFO] "
	debugLogLevelPrefix = " [DEBUG] "
	traceLogLevelPrefix = " [TRACE] "
	errorLogLevelPrefix = " [ERROR] "
	warnLogLevelPrefix  = " [WARN] "

	dateTimeFormatWithoutTimeZone = "2006-01-02 15:04:05:000"
)

type Logger interface {
	Info(message string)
	Debug(message string)
	Trace(message string)
	Error(message string, err ...error)
	Warn(message string)
	Close() error
}
