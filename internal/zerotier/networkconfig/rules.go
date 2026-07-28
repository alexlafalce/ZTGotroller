package networkconfig

import (
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const (
	ruleActionDrop   = byte(0)
	ruleActionAccept = byte(1)
	ruleFlagOr       = byte(0x40)
	ruleFlagNot      = byte(0x80)
)

// SerializeRules encodes the initial action-only rule subset. Unsupported
// rules fail closed instead of being silently emitted as zero-length entries.
func SerializeRules(rules []domain.Rule) ([]byte, error) {
	serialized := make([]byte, 0, len(rules)*2)
	for index, rule := range rules {
		var ruleType byte
		switch rule.Type {
		case "ACTION_DROP":
			ruleType = ruleActionDrop
		case "ACTION_ACCEPT":
			ruleType = ruleActionAccept
		default:
			return nil, fmt.Errorf("rule %d has unsupported type %q", index, rule.Type)
		}
		if len(rule.Parameters) != 0 {
			return nil, fmt.Errorf("rule %d action cannot have parameters", index)
		}
		if rule.Negate {
			ruleType |= ruleFlagNot
		}
		if rule.Or {
			ruleType |= ruleFlagOr
		}
		serialized = append(serialized, ruleType, 0)
	}
	return serialized, nil
}
