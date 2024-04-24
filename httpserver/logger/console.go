package logger

import (
	"fmt"
	"time"
)

const (
	infoLogLevelPrefix  = " [INFO] "
	debugLogLevelPrefix = " [DEBUG] "
	traceLogLevelPrefix = " [TRACE] "
	errorLogLevelPrefix = " [ERROR] "
	warnLogLevelPrefix  = " [WARN] "

	dateTimeFormatWithoutTimeZone = "2006-01-02 15:04:05.000"
)

func Info(message string) {
	fmt.Println(timeNow() + infoLogLevelPrefix + message)
}

func Debug(message string) {
	fmt.Println(timeNow() + debugLogLevelPrefix + message)
}

func Trace(message string) {
	fmt.Println(timeNow() + traceLogLevelPrefix + message)
}

func Error(message string, err ...error) {
	fmt.Println(timeNow()+errorLogLevelPrefix+message, err)
}

func Warn(message string) {
	fmt.Println(timeNow() + warnLogLevelPrefix + message)
}

func timeNow() string {
	return time.Now().Format(dateTimeFormatWithoutTimeZone)
}
