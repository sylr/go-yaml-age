package age

import (
	"strings"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

const (
	// YAMLTag tag that is used to identify data to crypt/decrypt
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

	armoredString := ArmoredString{Value: node.Value, Recipients: recipients}
	nodeInterface, err := armoredString.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}
