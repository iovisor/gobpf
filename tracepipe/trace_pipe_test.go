package tracepipe

import (
	"testing"
)

func TestParseTraceLine(t *testing.T) {
	lines := []string{
		"        chromium-15581 [000] d... 92783.722567: : Hello, World!",
		"            curl-18597 [000] dN..   463.471554: : kretprobe__tcp_v4_connect - pid_tgid 79873506822309\n",
		"      trace_pipe-23553 [000] .... 205825.968557: sys_enter: NR 0 (3, c420098000, 1000, 0, 0, 0)\n",
	}
	for _, line := range lines {
		_, err := parseTraceLine(line)
		if err != nil {
			t.Errorf("%q could not be parsed", line)
		}
	}
}
