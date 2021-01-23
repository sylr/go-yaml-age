package age

import (
	"bytes"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

// Wrapper is a struct that allows to decrypt age encrypted armored data in YAML
// as long that the data is tagged with "!crypto/age".
type Wrapper struct {
	// Value holds the struct that will be decrypted with the Identities.
	Value interface{}
	// Identities that will be used for decrypting.
	Identities []age.Identity
	// DiscardNoTag will not honour NoTag when decrypting so you can re-encrypt
	// with original tags.
	DiscardNoTag bool
}

// UnmarshalYAML takes yaml.Node and recursively decrypt data marked with the
// !crypto/age YAML tag.
func (w Wrapper) UnmarshalYAML(value *yaml.Node) error {
	resolved, err := w.resolve(value)
	if err != nil {
		return err
	}

	return resolved.Decode(w.Value)
}

func (w Wrapper) resolve(node *yaml.Node) (*yaml.Node, error) {
	// Recurse into sequence types
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = w.resolve(node.Content[i])
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
	case strings.HasPrefix(node.Tag, YAMLTag+":"):
		attrStr := node.Tag[12:]
		attrs := strings.Split(attrStr, ",")

		for _, attr := range attrs {
			lower := strings.ToLower(attr)
			switch lower {
			case "doublequoted", "singlequoted", "literal", "folded", "flow":
				if style != 0 {
					return nil, fmt.Errorf("Can't use more than one style attribute: %s", attrStr)
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
				return nil, fmt.Errorf("Unknown attribute: %s", attrStr)
			}
		}
	default:
		return node, nil
	}

	// Check the absence of armored age header and footer
	valueTrimmed := strings.TrimSpace(node.Value)
	if !strings.HasPrefix(valueTrimmed, armor.Header) || !strings.HasSuffix(valueTrimmed, armor.Footer) {
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
		return nil, fmt.Errorf("age: %w", err)
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(decryptedReader)

	if err != nil {
		return nil, err
	}

	tempTag := node.Tag
	node.SetString(buf.String())

	if w.DiscardNoTag || !notag {
		node.Tag = tempTag
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
