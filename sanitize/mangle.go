package sanitize

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// UserInputString is used to strip value of any \r \n to
// avoiding log injection / CWE-117
func UserInputString(key string, value string) zapcore.Field {
	esc := strings.Replace(value, "\n", "", -1)
	esc = strings.Replace(esc, "\r", "", -1)
	return zap.String(key, esc)
}

// NoLineBreaks removes linebreaks and carrage returns from string
func NoLineBreaks(value string) string {
	esc := strings.Replace(value, "\n", "", -1)
	esc = strings.Replace(esc, "\r", "", -1)
	return esc
}
