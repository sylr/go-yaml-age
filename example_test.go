package age_test

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	yamlage "sylr.dev/yaml/age/v3"
	yaml "sylr.dev/yaml/v3"
)

func ExampleWrapper() {
	yamlString := `
password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=
  -----END AGE ENCRYPTED FILE-----`

	buf := bytes.NewBufferString(yamlString)

	node := struct {
		Password yamlage.ArmoredString `yaml:"password"`
	}{}

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	w := yamlage.Wrapper{
		Value:      &node,
		Identities: []age.Identity{id},
	}
	decoder := yaml.NewDecoder(buf)
	err = decoder.Decode(&w)

	if err != nil {
		panic(err)
	}

	buf = bytes.NewBuffer(nil)
	encoder := yaml.NewEncoder(buf)
	encoder.SetIndent(2)
	err = encoder.Encode(&node)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", buf.String())
	// Output:
	// password: !crypto/age MyDatabasePassword
}

func ExampleWrapper_anonymous() {
	yamlString := `
password: !crypto/age:DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=
  -----END AGE ENCRYPTED FILE-----
---
password: !crypto/age:SingleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=
  -----END AGE ENCRYPTED FILE-----
---
password: !crypto/age:NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=
  -----END AGE ENCRYPTED FILE-----`

	buf := bytes.NewBufferString(yamlString)

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	node := &yaml.Node{}

	w := yamlage.Wrapper{
		Value:      node,
		Identities: []age.Identity{id},
	}

	output := new(bytes.Buffer)
	decoder := yaml.NewDecoder(buf)
	encoder := yaml.NewEncoder(output)
	encoder.SetIndent(2)

	for {
		err = decoder.Decode(&w)

		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		err = encoder.Encode(&node)

		if err != nil {
			panic(err)
		}

	}

	fmt.Printf("%s", output.String())

	// Output:
	// password: !crypto/age:DoubleQuoted "MyDatabasePassword"
	// ---
	// password: !crypto/age:SingleQuoted 'MyDatabasePassword'
	// ---
	// password: MyDatabasePassword
}

func ExampleArmoredString_encode() {
	rec, err := age.NewScryptRecipient("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	node := struct {
		Password yamlage.ArmoredString `yaml:"password"`
	}{
		Password: yamlage.ArmoredString{
			Value:      "MyDatabasePassword",
			Recipients: []age.Recipient{rec},
		},
	}

	buf := bytes.NewBuffer(nil)
	encoder := yaml.NewEncoder(buf)
	encoder.SetIndent(2)
	err = encoder.Encode(&node)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", buf.String())
}
