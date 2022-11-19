package age

import (
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

const (
	// YAMLTag tag that is used to identify data to encrypt/decrypt
	YAMLTag = "!crypto/age"
)

// MarshalYAML takes a *yaml.Node and []age.Recipient and recursively encrypt/marshal the Values.
func MarshalYAML(node *yaml.Node, recipients []age.Recipient) (*yaml.Node, error) {
	m := Marshaler{Recipients: recipients}

	return m.marshalYAML(node)
}

// MarshalYAML implements the yaml.Marshaler interface.
func NewMarshaler(node *yaml.Node) *Marshaler {
	return &Marshaler{
		node: node,
	}
}

// Marshaler marshals a *yaml.Node encrypting values with age.
type Marshaler struct {
	// node holds the *yaml.Node that will be encrypted with the Recipients.
	// Node must have been decoded with Wrapper.UnmarshalYAML.
	node *yaml.Node

	// Recipients that will be used for encrypting.
	Recipients []age.Recipient
}

// MarshalYAML implements the yaml.Marshaler interface.
func (m Marshaler) MarshalYAML() (interface{}, error) {
	return m.marshalYAML(m.node)
}

// marshalYAML is the internal implementation of MarshalYAML. We need the internal
// implementation to be able to return *yaml.Node instead of interface{} because
// the global MarshalYAML function needs to return an interface{} to comply with
// the yaml.Marshaler interface.
func (m Marshaler) marshalYAML(node *yaml.Node) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}

	// Recurse into sequence types
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = m.marshalYAML(node.Content[i])
				if err != nil {
					return nil, err
				}
			}
		}

		return node, nil
	}

	switch {
	case node.Tag == YAMLTag:
	case strings.HasPrefix(node.Tag, YAMLTag+":"):
	default:
		return node, nil
	}

	if isArmoredAgeFile(node.Value) {
		return node, nil
	}

	str := NewStringFromNode(node, m.Recipients)
	nodeInterface, err := str.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}

// isArmoredAgeFile checks whether the value starts with the AGE armor.Header
// and ends with the AGE armor Footer.
func isArmoredAgeFile(data string) bool {
	trimmed := strings.TrimSpace(data)
	return strings.HasPrefix(trimmed, armor.Header) && strings.HasSuffix(trimmed, armor.Footer)
}
