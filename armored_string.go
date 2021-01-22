package age

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

func NewArmoredString(str string, recipients []age.Recipient) ArmoredString {
	a := ArmoredString{}
	a.Recipients = recipients
	a.Node = &yaml.Node{}
	a.SetString(str)
	a.Tag = YAMLTag

	return a
}

func NewArmoredStringFromNode(node *yaml.Node, recipients []age.Recipient) ArmoredString {
	a := ArmoredString{}
	a.Recipients = recipients
	a.Node = node

	return a
}

// ArmoredString is a struct holding the string to encrypt and the intended recipients.
type ArmoredString struct {
	*yaml.Node
	Recipients []age.Recipient
}

// String implements the Stringer interface.
func (a *ArmoredString) String() string {
	return a.Value
}

// UnmarshalYAML pushes the yaml.Node.Value in the ArmoredString.Value.
func (a *ArmoredString) UnmarshalYAML(value *yaml.Node) error {
	a.Node = value

	return nil
}

// MarshalYAML encrypts the ArmoredString and marshals it to YAML. If Recipients
// is empty then the Value is kept unencrypted.
func (a ArmoredString) MarshalYAML() (interface{}, error) {
	node := yaml.Node{
		Kind:        a.Kind,
		Style:       a.Style,
		Tag:         a.Tag,
		Value:       a.Value,
		Anchor:      a.Anchor,
		HeadComment: a.HeadComment,
		LineComment: a.LineComment,
		FootComment: a.FootComment,
		Line:        a.Line,
		Column:      a.Column,
	}

	// If no recipients then do not encrypt.
	if len(a.Recipients) == 0 {
		node.Value = a.Value
		return &node, nil
	}

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, a.Recipients...)

	if err != nil {
		return nil, fmt.Errorf("age: %w", err)
	}

	_, err = io.WriteString(w, a.Value)

	if err != nil {
		return nil, err
	}

	w.Close()
	armorWriter.Close()

	node.Value = buf.String()

	return &node, nil
}
