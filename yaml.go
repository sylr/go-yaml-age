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
	return Marshaller{
		Node:       node,
		Recipients: recipients,
	}.marshalYAML()
}

// Marshaller marshals a *yaml.Node encrypting values with age.
type Marshaller struct {
	// Node holds the *yaml.Node that will be encrypted with the Recipients. Node must have been decoded with
	// Wrapper.UnmarshalYAML.
	// Warning: Node is modified in place.
	Node *yaml.Node
	// Recipients that will be used for encrypting.
	Recipients []age.Recipient
	// NoReencrypt tells Marshaller to not encrypt values that are already armored age files.
	NoReencrypt bool
}

// MarshalYAML implements the yaml.Marshaler interface.
func (m Marshaller) MarshalYAML() (interface{}, error) {
	return m.marshalYAML()
}

// marshalYAML is the internal implementation of MarshalYAML. We need the internal implementation to be able to return
// *yaml.Node instead of interface{} because the global MarshalYAML function needs to return *yaml.Node.
func (m Marshaller) marshalYAML() (*yaml.Node, error) {
	node := m.Node
	recipients := m.Recipients
	if node == nil {
		return nil, nil
	}
	// Recurse into sequence types
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = Marshaller{
					Node:        node.Content[i],
					Recipients:  recipients,
					NoReencrypt: m.NoReencrypt,
				}.marshalYAML()
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

	if m.NoReencrypt && isArmoredAgeFile(node.Value) {
		return node, nil
	}

	str := NewStringFromNode(node, recipients)
	nodeInterface, err := str.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}

// isArmoredAgeFile checks whether the value starts with armor.Header ("-----BEGIN AGE ENCRYPTED FILE-----") and ends
// with armor.Footer ("-----END AGE ENCRYPTED FILE-----").
func isArmoredAgeFile(data string) bool {
	trimmed := strings.TrimSpace(data)
	return strings.HasPrefix(trimmed, armor.Header) && strings.HasSuffix(trimmed, armor.Footer)
}
