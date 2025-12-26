package utils

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type Logger struct {
	logger *log.Logger
	name   string
	level  int
}

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

func NewLogger(name string) *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile),
		name:   name,
		level:  LevelInfo,
	}
}

func (l *Logger) SetLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		l.level = LevelDebug
	case "info":
		l.level = LevelInfo
	case "warn", "warning":
		l.level = LevelWarn
	case "error":
		l.level = LevelError
	}
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	if l.level <= LevelDebug {
		l.log("DEBUG", msg, args...)
	}
}

func (l *Logger) Info(msg string, args ...interface{}) {
	if l.level <= LevelInfo {
		l.log("INFO", msg, args...)
	}
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	if l.level <= LevelWarn {
		l.log("WARN", msg, args...)
	}
}

func (l *Logger) Error(msg string, args ...interface{}) {
	if l.level <= LevelError {
		l.log("ERROR", msg, args...)
	}
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log("FATAL", msg, args...)
	os.Exit(1)
}

func (l *Logger) log(level, msg string, args ...interface{}) {
	var logArgs []interface{}
	logArgs = append(logArgs, fmt.Sprintf("[%s] [%s]", l.name, level))
	logArgs = append(logArgs, msg)

	if len(args) > 0 {
		for i := 0; i < len(args); i += 2 {
			if i+1 < len(args) {
				logArgs = append(logArgs, fmt.Sprintf("%v=%v", args[i], args[i+1]))
			} else {
				logArgs = append(logArgs, args[i])
			}
		}
	}

	l.logger.Println(logArgs...)
}
