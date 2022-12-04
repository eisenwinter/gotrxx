package sanitize

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// UserInputString is used to strip value of any \r \n to
// avoiding log injection / CWE-117
func UserInputString(key string, value string) zapcore.Field {
	esc := NoLineBreaks(value)
	return zap.String(key, esc)
}

// NoLineBreaks removes linebreaks and carrage returns from string
func NoLineBreaks(value string) string {
	esc := strings.ReplaceAll(value, "\n", "")
	esc = strings.ReplaceAll(esc, "\r", "")
	return esc
}
