package networkconfig

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

func TestIssuePolicyCredentials(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	now := time.Unix(1_700_000_000, 0).UTC()
	defaultTag := uint32(3)
	network := domain.NewNetwork(networkID, now)
	network.Capabilities = []domain.Capability{{
		ID: 7, Default: true, Rules: []domain.Rule{{Type: "ACTION_ACCEPT"}},
	}}
	network.Tags = []domain.TagDefinition{{ID: 9, Default: &defaultTag}}
	member := domain.NewMember(networkID, controller.Address(), now)

	capabilities, tags, err := issuePolicyCredentials(
		network, member, uint64(now.UnixMilli()), controller,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 141 {
		t.Fatalf("capability length = %d, want 141", len(capabilities))
	}
	if len(tags) != 135 {
		t.Fatalf("tag length = %d, want 135", len(tags))
	}
	if binary.BigEndian.Uint32(capabilities[16:20]) != 7 ||
		binary.BigEndian.Uint32(tags[16:20]) != 9 ||
		binary.BigEndian.Uint32(tags[20:24]) != 3 {
		t.Fatalf("unexpected credential IDs/values: cap=%x tag=%x", capabilities[:24], tags[:24])
	}

	var capabilitySignature identity.Signature
	copy(capabilitySignature[:], capabilities[38:134])
	capabilitySigningPayload := withPolicySentinels(append(
		append([]byte(nil), capabilities[:25]...), 0, 0,
	))
	if !controller.Public().Verify(capabilitySigningPayload, capabilitySignature) {
		t.Fatal("capability signature does not verify")
	}
	var tagSignature identity.Signature
	copy(tagSignature[:], tags[37:133])
	tagSigningPayload := withPolicySentinels(append(append([]byte(nil), tags[:34]...), 0, 0))
	if !controller.Public().Verify(tagSigningPayload, tagSignature) {
		t.Fatal("tag signature does not verify")
	}
}

func TestIssuePolicyCredentialsUsesMemberValues(t *testing.T) {
	controller, _ := testIdentity()
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	now := time.Now().UTC()
	network := domain.NewNetwork(networkID, now)
	network.Capabilities = []domain.Capability{{
		ID: 5, Rules: []domain.Rule{ruleWithParameters(t, "MATCH_ETHERTYPE", map[string]any{
			"etherType": 2048,
		})},
	}}
	network.Tags = []domain.TagDefinition{{ID: 2}}
	member := domain.NewMember(networkID, controller.Address(), now)
	member.Capabilities = []uint32{5}
	member.Tags = []domain.TagValue{{ID: 2, Value: 99}}

	capabilities, tags, err := issuePolicyCredentials(network, member, 1, controller)
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) == 0 || binary.BigEndian.Uint32(tags[20:24]) != 99 {
		t.Fatalf("member credentials missing: cap=%x tag=%x", capabilities, tags)
	}
}

func ruleWithParameters(t *testing.T, ruleType string, values map[string]any) domain.Rule {
	t.Helper()
	rule := domain.Rule{Type: ruleType, Parameters: make(map[string]json.RawMessage)}
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		rule.Parameters[key] = raw
	}
	return rule
}
