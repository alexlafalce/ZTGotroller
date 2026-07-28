package networkconfig

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

func TestSerializeBasicRules(t *testing.T) {
	serialized, err := SerializeRules([]domain.Rule{
		{Type: "ACTION_ACCEPT"},
		{Type: "ACTION_DROP", Negate: true, Or: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serialized, []byte{1, 0, 0xc0, 0}) {
		t.Fatalf("rules = %x", serialized)
	}
}

func TestSerializeAdvancedRules(t *testing.T) {
	rules := []domain.Rule{
		ruleWith("MATCH_ETHERTYPE", map[string]any{"etherType": 0x0800}),
		ruleWith("MATCH_IPV4_SOURCE", map[string]any{"ip": "10.0.0.0/8"}),
		ruleWith("MATCH_IP_DEST_PORT_RANGE", map[string]any{"start": 443, "end": 443}),
		ruleWith("MATCH_TAG_SENDER", map[string]any{"id": 7, "value": 9}),
		ruleWith("ACTION_TEE", map[string]any{
			"address": "abcdef1234", "flags": 2, "length": 128,
		}),
	}
	serialized, err := SerializeRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{
		37, 2, 0x08, 0x00,
		31, 5, 10, 0, 0, 0, 8,
		40, 4, 0x01, 0xbb, 0x01, 0xbb,
		49, 8, 0, 0, 0, 7, 0, 0, 0, 9,
		2, 14, 0, 0, 0, 0xab, 0xcd, 0xef, 0x12, 0x34,
		0, 0, 0, 2, 0, 128,
	}
	if !bytes.Equal(serialized, expected) {
		t.Fatalf("rules = %x, want %x", serialized, expected)
	}
}

func TestSerializeIntegerRange(t *testing.T) {
	rule := ruleWith("MATCH_INTEGER_RANGE", map[string]any{
		"start": "0000000000000010", "end": "0000000000000020",
		"idx": 14, "bits": 32, "little": true,
	})
	serialized, err := SerializeRules([]domain.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) != 21 || serialized[0] != 51 || serialized[1] != 19 ||
		serialized[20] != 0x9f {
		t.Fatalf("unexpected integer rule: %x", serialized)
	}
}

func TestSerializeRulesRejectsInvalidTypeAndFields(t *testing.T) {
	if _, err := SerializeRules([]domain.Rule{{Type: "UNKNOWN"}}); err == nil {
		t.Fatal("expected unsupported rule error")
	}
	if _, err := SerializeRules([]domain.Rule{{Type: "MATCH_ETHERTYPE"}}); err == nil {
		t.Fatal("expected missing field error")
	}
	if _, err := SerializeRules([]domain.Rule{
		ruleWith("MATCH_IP_DEST_PORT_RANGE", map[string]any{"start": 100, "end": 10}),
	}); err == nil {
		t.Fatal("expected invalid range error")
	}
}

func ruleWith(ruleType string, parameters map[string]any) domain.Rule {
	result := domain.Rule{Type: ruleType, Parameters: make(map[string]json.RawMessage)}
	for key, value := range parameters {
		result.Parameters[key], _ = json.Marshal(value)
	}
	return result
}
