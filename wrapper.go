package age

import (
	"bytes"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

const (
	// YAMLTag tag that is used to identify data to encrypt/decrypt
	YAMLTag       = "!crypto/age"
	YAMLTagPrefix = "!crypto/age:"
)

var _ yaml.Unmarshaler = (*Wrapper)(nil)
var _ yaml.Marshaler = (*Wrapper)(nil)

// Wrapper is a struct used as a wrapper for yaml.Marshal and yaml.Unmarshal.
type Wrapper struct {
	// Value holds the struct that will either be decrypted with the given
	// Identities or encrypted with the given Recipients.
	Value interface{}

	// Identities that will be used to try decrypting encrypted Value.
	Identities []age.Identity

	// Recipients that will be used for encrypting un-encrypted Value.
	Recipients []age.Recipient

	// DiscardNoTag instructs the Unmarshaler to not honour the NoTag
	// `!crypto/age` tag attribute. This is useful when re-keying data.
	DiscardNoTag bool

	// ForceNoTag strip the `!crypto/age` tags from the Marshaler output.
	ForceNoTag bool

	// NoDecrypt inscruts the Unmarshaler to leave encrypted data encrypted.
	// This is useful when you want to Marshal new un-encrytped data in a
	// document already containing encrypted data.
	NoDecrypt bool
}

// UnmarshalYAML takes a yaml.Node and recursively decrypt nodes marked with the
// `!crypto/age` YAML tag.
func (w Wrapper) UnmarshalYAML(value *yaml.Node) error {
	decoded, err := w.decode(value)
	if err != nil {
		return err
	}

	return decoded.Decode(w.Value)
}

func (w Wrapper) decode(node *yaml.Node) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}

	// Recurse into sequence types
	if node.Kind == yaml.DocumentNode || node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = w.decode(node.Content[i])
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var notag bool
	var style yaml.Style

	switch {
	case node.Tag == YAMLTag:
	case strings.HasPrefix(node.Tag, YAMLTagPrefix):
		attrStr := node.Tag[len(YAMLTagPrefix):]
		attrs := strings.Split(attrStr, ",")

		for _, attr := range attrs {
			lower := strings.ToLower(attr)
			switch lower {
			case "doublequoted", "singlequoted", "literal", "folded", "flow":
				if style != 0 {
					return nil, fmt.Errorf("%w: %s", ErrMoreThanOneStyleAttribute, attrStr)
				}
				switch lower {
				case "doublequoted":
					style = yaml.DoubleQuotedStyle
				case "singlequoted":
					style = yaml.SingleQuotedStyle
				case "literal":
					style = yaml.LiteralStyle
				case "folded":
					style = yaml.FoldedStyle
				case "flow":
					style = yaml.FlowStyle
				}
			case "notag":
				notag = true
			default:
				return nil, fmt.Errorf("%w: %s", ErrUnknownAttribute, attrStr)
			}
		}
	default:
		return node, nil
	}

	if w.ForceNoTag {
		node.Tag = ""
	}

	// Check the absence of armored age header and footer
	if w.NoDecrypt || !isArmoredAgeFile(node.Value) {
		return node, nil
	}

	var str string
	err := node.Decode(&str)

	if err != nil {
		return nil, err
	}

	stringReader := strings.NewReader(str)
	armoredReader := armor.NewReader(stringReader)
	decryptedReader, err := age.Decrypt(armoredReader, w.Identities...)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUpstreamAgeError, err)
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(decryptedReader)

	if err != nil {
		return nil, err
	}

	tempTag := node.Tag
	node.SetString(buf.String())

	if !w.ForceNoTag {
		if w.DiscardNoTag || !notag {
			node.Tag = tempTag
		}
	}

	if style == 0 {
		if strings.Contains(node.Value, "\n") {
			node.Style = yaml.LiteralStyle
		} else {
			node.Style = yaml.FlowStyle
		}
	} else {
		node.Style = style
	}

	return node, nil
}

// MarshalYAML recursively encrypts Value.
func (w Wrapper) MarshalYAML() (interface{}, error) {
	switch v := w.Value.(type) {
	case *yaml.Node:
		return w.encode(v)
	default:
		return nil, fmt.Errorf("%w: %#v", ErrUnsupportedValueType, v)
	}
}

// marshalYAML is the internal implementation of MarshalYAML. We need the internal
// implementation to be able to return *yaml.Node instead of interface{} because
// the global MarshalYAML function needs to return an interface{} to comply with
// the yaml.Marshaler interface.
func (w Wrapper) encode(node *yaml.Node) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}

	// Recurse into sequence types
	if node.Kind == yaml.DocumentNode || node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = w.encode(node.Content[i])
				if err != nil {
					return nil, err
				}
			}
		}

		return node, nil
	}

	switch {
	case node.Tag == YAMLTag:
	case strings.HasPrefix(node.Tag, YAMLTagPrefix):
	default:
		return node, nil
	}

	if isArmoredAgeFile(node.Value) {
		return node, nil
	}

	str := NewStringFromNode(node, w.Recipients)
	nodeInterface, err := str.MarshalYAML()

	return nodeInterface.(*yaml.Node), err
}

// isArmoredAgeFile checks whether the value starts with the AGE armor.Header
// and ends with the AGE armor Footer.
func isArmoredAgeFile(data string) bool {
	trimmed := strings.TrimSpace(data)
	return strings.HasPrefix(trimmed, armor.Header) && strings.HasSuffix(trimmed, armor.Footer)
}
