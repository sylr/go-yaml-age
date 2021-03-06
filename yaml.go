package age

import (
	"strings"

	"filippo.io/age"
	"sylr.dev/yaml/v3"
)

const (
	// YAMLTag tag that is used to identify data to encrypt/decrypt
	YAMLTag = "!crypto/age"
)

// MarshalYAML takes a *yaml.Node and []age.Recipient and recursively encrypt/marshal the Values.
func MarshalYAML(node *yaml.Node, recipients []age.Recipient) (*yaml.Node, error) {
	// Recurse into sequence types
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = MarshalYAML(node.Content[i], recipients)
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

	str := NewStringFromNode(node, recipients)
	nodeInterface, err := str.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}
