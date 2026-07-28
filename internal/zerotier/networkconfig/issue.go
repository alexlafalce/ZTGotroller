package networkconfig

import (
	"errors"
	"fmt"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

type IssueInput struct {
	Network         domain.Network
	Member          domain.Member
	Recipient       identity.Identity
	Controller      identity.Identity
	IssuedAt        time.Time
	Revision        uint64
	MaxChunkData    int
	CredentialDelta time.Duration
}

type IssuedConfig struct {
	Dictionary []byte
	Chunks     [][]byte
	COM        CertificateOfMembership
	COO        *CertificateOfOwnership
}

// IssueAuthorizedConfig assembles all credentials and signed chunks needed by
// an authorized member. Transport-level packet encryption is deliberately a
// separate concern.
func IssueAuthorizedConfig(input IssueInput) (IssuedConfig, error) {
	if !input.Member.Authorized {
		return IssuedConfig{}, errors.New("member is not authorized")
	}
	if input.Member.NetworkID != input.Network.ID {
		return IssuedConfig{}, errors.New("member belongs to a different network")
	}
	if input.Recipient.Address() != input.Member.NodeID {
		return IssuedConfig{}, errors.New("recipient identity does not match member")
	}
	if !input.Recipient.LocallyValidate() {
		return IssuedConfig{}, errors.New("recipient identity failed local proof validation")
	}
	controllerID, err := input.Network.ID.ControllerID()
	if err != nil {
		return IssuedConfig{}, err
	}
	if input.Controller.Address() != controllerID {
		return IssuedConfig{}, errors.New("controller identity does not own network")
	}
	if !input.Controller.HasPrivate() {
		return IssuedConfig{}, errors.New("controller identity has no private key")
	}
	if input.IssuedAt.IsZero() {
		return IssuedConfig{}, errors.New("issue time is required")
	}
	if input.IssuedAt.UnixMilli() < 0 {
		return IssuedConfig{}, errors.New("issue time cannot precede the Unix epoch")
	}
	if input.Revision == 0 {
		return IssuedConfig{}, errors.New("configuration revision cannot be zero")
	}
	if input.CredentialDelta == 0 {
		input.CredentialDelta = DefaultCredentialTimeMaxDelta
	}
	if input.CredentialDelta < 0 {
		return IssuedConfig{}, errors.New("credential delta cannot be negative")
	}

	timestamp := uint64(input.IssuedAt.UnixMilli())
	delta := uint64(input.CredentialDelta.Milliseconds())
	com, err := NewCertificateOfMembership(
		timestamp, delta, input.Network.ID, input.Recipient, input.Controller,
	)
	if err != nil {
		return IssuedConfig{}, fmt.Errorf("issue COM: %w", err)
	}
	comBytes, err := com.MarshalBinary()
	if err != nil {
		return IssuedConfig{}, fmt.Errorf("serialize COM: %w", err)
	}

	var coo *CertificateOfOwnership
	var cooBytes []byte
	if len(input.Member.IPAssignments) > 0 {
		credential, err := NewCertificateOfOwnership(
			input.Network.ID,
			timestamp,
			1,
			input.Member.NodeID,
			input.Member.IPAssignments,
			input.Controller,
		)
		if err != nil {
			return IssuedConfig{}, fmt.Errorf("issue COO: %w", err)
		}
		coo = &credential
		cooBytes, err = credential.MarshalBinary()
		if err != nil {
			return IssuedConfig{}, fmt.Errorf("serialize COO: %w", err)
		}
	}

	dictionary, err := BuildDictionary(ConfigInput{
		Network:                 input.Network,
		Member:                  input.Member,
		IssuedAt:                input.IssuedAt,
		Revision:                input.Revision,
		CredentialTimeMaxDelta:  input.CredentialDelta,
		CertificateOfMembership: comBytes,
		CertificatesOfOwnership: cooBytes,
	})
	if err != nil {
		return IssuedConfig{}, fmt.Errorf("build dictionary: %w", err)
	}
	chunks, err := BuildSignedChunks(
		input.Network.ID,
		dictionary,
		input.Revision,
		input.MaxChunkData,
		input.Controller,
	)
	if err != nil {
		return IssuedConfig{}, fmt.Errorf("sign config chunks: %w", err)
	}
	return IssuedConfig{
		Dictionary: dictionary,
		Chunks:     chunks,
		COM:        com,
		COO:        coo,
	}, nil
}
