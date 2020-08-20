package main

import (
	"github.com/juju/loggo"
	"time"
	"path/filepath"
	"strings"
	"os"
	"fmt"
)

type loggoWriter struct {
	log loggo.Logger
}

func (l loggoWriter) Write(data []byte) (int, error) {
	l.log.Warningf("%s", data)
	return len(data), nil
}

func LogFormatterDT(entry loggo.Entry) string {
	var prefix string
	ts := entry.Timestamp.In(time.Local).Format("2006-01-02 15:04:05.123 -0700")
	filename := filepath.Base(entry.Filename)
	prefix = fmt.Sprintf("%s %s %s %s:%d", ts, entry.Level, entry.Module, filename, entry.Line)

	var out string
	for _, line := range strings.Split(entry.Message, "\n") {
		if len(line) == 0 { continue }
		out += fmt.Sprintf("[%s] %s\n", prefix, line)
	}

	return out[:len(out)-1]
}

func LogFormatterDN(entry loggo.Entry) string {
	var prefix string
	filename := filepath.Base(entry.Filename)
	prefix = fmt.Sprintf("%s %s %s:%d", entry.Level, entry.Module, filename, entry.Line)

	var out string
	for _, line := range strings.Split(entry.Message, "\n") {
		if len(line) == 0 { continue }
		out += fmt.Sprintf("[%s] %s\n", prefix, line)
	}

	return out[:len(out)-1]
}

func LogFormatterNT(entry loggo.Entry) string {
	var prefix string
	ts := entry.Timestamp.In(time.Local).Format("2006-01-02 15:04:05.123 -0700")
	prefix = fmt.Sprintf("%s %s", ts, entry.Module)

	var out string
	for _, line := range strings.Split(entry.Message, "\n") {
		if len(line) == 0 { continue }
		out += fmt.Sprintf("[%s] %s\n", prefix, line)
	}

	return out[:len(out)-1]
}

func LogFormatterNN(entry loggo.Entry) string {
	var prefix string
	prefix = fmt.Sprintf("%s", entry.Module)

	var out string
	for _, line := range strings.Split(entry.Message, "\n") {
		if len(line) == 0 { continue }
		out += fmt.Sprintf("[%s] %s\n", prefix, line)
	}

	return out[:len(out)-1]
}

func initLoggingDebug(name string, showTime bool) loggo.Logger {
	if showTime {
		loggo.ReplaceDefaultWriter(loggo.NewSimpleWriter(os.Stderr, LogFormatterDT))
	} else {
		loggo.ReplaceDefaultWriter(loggo.NewSimpleWriter(os.Stderr, LogFormatterDN))
	}
	return loggo.GetLogger(name)
}

func initLoggingNormal(name string, showTime bool) loggo.Logger {
	if showTime {
		loggo.ReplaceDefaultWriter(loggo.NewSimpleWriter(os.Stderr, LogFormatterNT))
	} else {
		loggo.ReplaceDefaultWriter(loggo.NewSimpleWriter(os.Stderr, LogFormatterNN))
	}
	return loggo.GetLogger(name)
}
