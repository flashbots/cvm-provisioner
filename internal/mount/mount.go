// Package mount is a tiny helper for inspecting /proc/mounts.
package mount

import (
	"bufio"
	"os"
	"strings"
)

// IsMounted returns true if target appears as a mount point in /proc/mounts.
func IsMounted(target string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[1] == target {
			return true
		}
	}
	return false
}
