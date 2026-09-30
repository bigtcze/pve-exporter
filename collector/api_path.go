package collector

import (
	"fmt"
	"net/url"
)

func apiPathf(format string, args ...any) string {
	escaped := make([]any, len(args))
	for i, arg := range args {
		if segment, ok := arg.(string); ok {
			escaped[i] = url.PathEscape(segment)
		} else {
			escaped[i] = arg
		}
	}
	return fmt.Sprintf(format, escaped...)
}
