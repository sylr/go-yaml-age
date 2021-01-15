package age

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// ArmoredString is a struct holding the string to encrypt and the intended recipients.
type ArmoredString struct {
	Value      string
	Recipients []age.Recipient
	Tag        string
}

// String implements the Stringer interface.
func (a *ArmoredString) String() string {
	return a.Value
}

// UnmarshalYAML pushes the yaml.Node.Value in the ArmoredString.Value.
func (a *ArmoredString) UnmarshalYAML(value *yaml.Node) error {
	a.Value = value.Value

	return nil
}

// MarshalYAML encrypts the ArmoredString and marshals it to YAML. If Recipients
// is empty then the Value is kept unencrypted.
func (a ArmoredString) MarshalYAML() (interface{}, error) {
	var tag string

	if len(a.Tag) > 0 {
		tag = a.Tag
	} else {
		tag = YAMLTag
	}

	node := yaml.Node{
		Kind: yaml.ScalarNode,
		Tag:  tag,
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
