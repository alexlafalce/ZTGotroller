package domain

import (
	"fmt"
	"strconv"
)

const (
	nodeIDHexLength    = 10
	networkIDHexLength = 16
)

type NodeID string

func ParseNodeID(value string) (NodeID, error) {
	if err := validateHexID(value, nodeIDHexLength); err != nil {
		return "", fmt.Errorf("invalid node ID: %w", err)
	}
	return NodeID(value), nil
}

func (id NodeID) Validate() error {
	_, err := ParseNodeID(string(id))
	return err
}

type NetworkID string

func ParseNetworkID(value string) (NetworkID, error) {
	if err := validateHexID(value, networkIDHexLength); err != nil {
		return "", fmt.Errorf("invalid network ID: %w", err)
	}
	return NetworkID(value), nil
}

func NewNetworkID(controller NodeID, sequence uint32) NetworkID {
	return NetworkID(fmt.Sprintf("%s%06x", controller, sequence&0x00ffffff))
}

func (id NetworkID) Validate() error {
	_, err := ParseNetworkID(string(id))
	return err
}

func (id NetworkID) ControllerID() (NodeID, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return NodeID(string(id)[:nodeIDHexLength]), nil
}

func validateHexID(value string, length int) error {
	if len(value) != length {
		return fmt.Errorf("must contain exactly %d lowercase hexadecimal characters", length)
	}
	if _, err := strconv.ParseUint(value, 16, 64); err != nil {
		return fmt.Errorf("must be hexadecimal")
	}
	for _, character := range value {
		if character >= 'A' && character <= 'F' {
			return fmt.Errorf("must use lowercase hexadecimal")
		}
	}
	return nil
}
