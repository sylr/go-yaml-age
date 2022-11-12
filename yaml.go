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

type marshallerOptions struct {
	ignoreEncrypted bool
}

// MarshalYAMLOption is an option for MarshalYAML.
type MarshalYAMLOption func(*marshallerOptions)

// NoReencrypt tells MarshalYAML to not encrypt values that are already encrypted. It determines this by checking if the
// value starts with armor.Header ("-----BEGIN AGE ENCRYPTED FILE-----").
func NoReencrypt() MarshalYAMLOption {
	return func(m *marshallerOptions) {
		m.ignoreEncrypted = true
	}
}

// MarshalYAML takes a *yaml.Node and []age.Recipient and recursively encrypt/marshal the Values.
func MarshalYAML(node *yaml.Node, recipients []age.Recipient, options ...MarshalYAMLOption) (*yaml.Node, error) {

	opts := &marshallerOptions{}
	for _, o := range options {
		o(opts)
	}
	// Recurse into sequence types
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = MarshalYAML(node.Content[i], recipients, options...)
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

	if opts.ignoreEncrypted && strings.HasPrefix(strings.TrimSpace(node.Value), armor.Header) {
		return node, nil
	}

	str := NewStringFromNode(node, recipients)
	nodeInterface, err := str.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}
