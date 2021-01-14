package age

import (
	"bytes"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// Wrapper is a struct that allows to decrypt crypted armored data in YAML as long
// that the data is tagged with "!crypto/age".
//
//     database_login: mylogin
//     database_password: !crypto/age |
//       -----BEGIN AGE ENCRYPTED FILE-----
//       ...
//       ...
//       -----END AGE ENCRYPTED FILE-----
//
// Example:
//
//     bytes := []byte(...)
//     node := struct {
//     	Key1 string `yaml:"key1"`
//     	Key2 string `yaml:"key2"`
//     }{}
//     w := Wrapper{
//     	Value:      &node,
//     	Identities: []age.Indentity{...},
//     }
//     decoder := yaml.NewDecoder(in)
//     err := decoder.Decode(&w)
//
// If you intend to only display the YAML data with unencryted values you should
// use `&yaml.Node{}` as `Wrapper.Value` so you can marshal it later with comments.
//
type Wrapper struct {
	// Value holds the struct that will be decrypted with the Identities.
	Value interface{}
	// Identities that will be used for decrypting.
	Identities []age.Identity
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

	if node.Tag != YAMLTag {
		return node, nil
	}

	// Check the absence of armored age header and footer
	valueTrimmed := strings.TrimSpace(node.Value)
	if !strings.HasPrefix(valueTrimmed, armor.Header) || !strings.HasSuffix(valueTrimmed, armor.Footer) {
		return node, nil
	}

	var armoredString string
	err := node.Decode(&armoredString)

	if err != nil {
		return nil, err
	}

	armoredStringReader := strings.NewReader(armoredString)
	armoredReader := armor.NewReader(armoredStringReader)
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
	node.Tag = tempTag

	return node, nil
}
