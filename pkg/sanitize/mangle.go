package sanitize

import (
	"strings"
)

// UserInputString is used to strip value of any \r \n to
// avoiding log injection / CWE-117
func UserInputString(value string) string {
	return NoLineBreaks(value)
}

// NoLineBreaks removes linebreaks and carrage returns from string
func NoLineBreaks(value string) string {
	esc := strings.ReplaceAll(value, "\n", "")
	esc = strings.ReplaceAll(esc, "\r", "")
	return esc
}
