package logger

import (
	"fmt"
	"time"
)

func NewConsoleLogger() Logger {
	return &ConsoleLogger{}
}

type ConsoleLogger struct{}

func (cl *ConsoleLogger) Info(message string) {
	fmt.Println(cl.timeNow() + infoLogLevelPrefix + message)
}

func (cl *ConsoleLogger) Debug(message string) {
	fmt.Println(cl.timeNow() + debugLogLevelPrefix + message)
}

func (cl *ConsoleLogger) Trace(message string) {
	fmt.Println(cl.timeNow() + traceLogLevelPrefix + message)
}

func (cl *ConsoleLogger) Error(message string, err ...error) {
	fmt.Println(cl.timeNow()+errorLogLevelPrefix+message, err)
}

func (cl *ConsoleLogger) Warn(message string) {
	fmt.Println(cl.timeNow() + warnLogLevelPrefix + message)
}

func (cl *ConsoleLogger) Close() error {
	return nil
}

func (cl *ConsoleLogger) timeNow() string {
	return time.Now().Format(dateTimeFormatWithoutTimeZone)
}
