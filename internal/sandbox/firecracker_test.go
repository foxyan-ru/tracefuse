package sandbox

import (
	"strings"
	"testing"

	"github.com/tracefuse/tracefuse/internal/trace"
)

func TestConsoleProtocol(t *testing.T) {
	tr := &trace.Trace{SandboxID: "sb-1"}
	var out strings.Builder
	for _, l := range []string{
		`[    0.120000] Run /sbin/tracefuse-init as init process`,
		`TFEVT {"event":"exec","process":"sh","pid":42,"path":"/usr/bin/python3","source":"ebpf"}`,
		`TFEVT {not json`,
		`TFOUT hello`,
		`[    0.900000] TFBLOCK IN= OUT=eth0 SRC=172.16.0.2 DST=169.254.169.254 LEN=60 PROTO=TCP SPT=40000 DPT=80`,
		`TFEXIT 0`,
	} {
		handleConsoleLine(tr, &out, l)
	}
	if len(tr.Events) != 2 || tr.Events[1].Action != "blocked" || tr.Events[1].Destination != "169.254.169.254:80" {
		t.Fatalf("events: %+v", tr.Events)
	}
	if tr.Events[0].SandboxID != "sb-1" {
		t.Fatal("sandbox id must come from controller")
	}
	if out.String() != "hello\n" || tr.ExitCode != 0 {
		t.Fatalf("stdout=%q exit=%d", out.String(), tr.ExitCode)
	}
}
