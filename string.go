package age

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

// NewString takes a string to encrypt and the targeted recipients then
// returns a String ready to be Marshalled.
func NewString(str string, recipients []age.Recipient) String {
	s := String{}
	s.Recipients = recipients
	s.Node = &yaml.Node{}
	s.SetString(str)
	s.Tag = YAMLTag

	return s
}

// NewStringFromNode takes a *yaml.Node and recipients and returns a String.
func NewStringFromNode(node *yaml.Node, recipients []age.Recipient) String {
	s := String{}
	s.Recipients = recipients
	s.Node = node

	return s
}

// String holds a string to encrypt and the targeted recipients.
// It embeds *yaml.Node.
type String struct {
	*yaml.Node
	Recipients []age.Recipient
}

// String implements the Stringer interface.
func (s *String) String() string {
	return s.Value
}

// UnmarshalYAML pushes the yaml.Node in the String.Node.
func (s *String) UnmarshalYAML(value *yaml.Node) error {
	s.Node = value

	return nil
}

// MarshalYAML encrypts the String and marshals it to YAML. If Recipients
// is empty then the Value is kept unencrypted.
func (s String) MarshalYAML() (interface{}, error) {
	node := yaml.Node{
		Kind:        s.Kind,
		Style:       s.Style,
		Tag:         s.Tag,
		Value:       s.Value,
		Anchor:      s.Anchor,
		HeadComment: s.HeadComment,
		LineComment: s.LineComment,
		FootComment: s.FootComment,
		Line:        s.Line,
		Column:      s.Column,
	}

	// If no recipients then do not encrypt.
	if len(s.Recipients) == 0 {
		node.Value = s.Value
		return &node, nil
	}

	// Force yaml literal string for encrypted data
	node.Style = yaml.LiteralStyle

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)
	encryptWriter, err := age.Encrypt(armorWriter, s.Recipients...)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUpstreamAgeError, err)
	}

	_, err = io.WriteString(encryptWriter, s.Value)

	if err != nil {
		return nil, err
	}

	encryptWriter.Close()
	armorWriter.Close()

	node.Value = strings.TrimSuffix(buf.String(), "\n")

	return &node, nil
}
