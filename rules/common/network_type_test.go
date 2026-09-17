package common

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// An echo is a flow like any other, so a profile can send every one of them to
// the outbound that is able to carry it.
func TestNetworkTypeCarriesICMP(t *testing.T) {
	rule, err := NewNetworkType("icmp", "pc")
	if err != nil {
		t.Fatalf("NewNetworkType: %v", err)
	}
	if matched, adapter := rule.Match(&C.Metadata{NetWork: C.ICMP}, C.RuleMatchHelper{}); !matched || adapter != "pc" {
		t.Fatalf("an ICMP flow matched %v to %q", matched, adapter)
	}
	if matched, _ := rule.Match(&C.Metadata{NetWork: C.UDP}, C.RuleMatchHelper{}); matched {
		t.Fatal("a UDP flow matched the ICMP rule")
	}
	if rule.Payload() != "icmp" {
		t.Fatalf("the rule says %q", rule.Payload())
	}
}
