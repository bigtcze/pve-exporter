package collector

import "fmt"

func apiPathf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
