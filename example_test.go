package age_test

import (
	"bytes"
	"fmt"

	"filippo.io/age"
	yaml "gopkg.in/yaml.v3"
	yamlage "sylr.dev/yaml/age/v3"
)

func ExampleWrapper() {
	yamlString := `
database_login: "service_1"
database_host: "db.company.com:5432"
database_password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=
  -----END AGE ENCRYPTED FILE-----`

	buf := bytes.NewBufferString(yamlString)

	node := struct {
		DatabaseLogin    string                `yaml:"database_login"`
		DatabaseHost     string                `yaml:"database_host"`
		DatabasePassword yamlage.ArmoredString `yaml:"database_password"`
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
	// database_login: service_1
	// database_host: db.company.com:5432
	// database_password: !crypto/age MyDatabasePassword
}

func ExampleWrapper_anonymous() {
	yamlString := `
database_login: "service_1"
database_host: "db.company.com:5432"
database_password: !crypto/age |
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
	// database_login: "service_1"
	// database_host: "db.company.com:5432"
	// database_password: !crypto/age |-
	//   MyDatabasePassword
}

func ExampleArmoredString_encode() {
	rec, err := age.NewScryptRecipient("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	node := struct {
		DatabaseLogin    string                `yaml:"database_login"`
		DatabaseHost     string                `yaml:"database_host"`
		DatabasePassword yamlage.ArmoredString `yaml:"database_password"`
	}{
		DatabaseLogin: "service_1",
		DatabaseHost:  "db.company.com:5432",
		DatabasePassword: yamlage.ArmoredString{
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
