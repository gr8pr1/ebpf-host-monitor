//go:build bpf_test

package bpf_test

import "testing"

func TestBPFProgramHarnessPlaceholder(t *testing.T) {
	t.Skip("requires CAP_BPF, kernel headers, and loaded BPF object; run manually")
}
