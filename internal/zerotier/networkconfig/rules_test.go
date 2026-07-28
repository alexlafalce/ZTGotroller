package networkconfig

import (
	"bytes"
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

func TestSerializeRulesRejectsUnsupportedType(t *testing.T) {
	if _, err := SerializeRules([]domain.Rule{{Type: "MATCH_ETHERTYPE"}}); err == nil {
		t.Fatal("expected unsupported rule error")
	}
}
