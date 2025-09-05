package age_test

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	yaml "go.yaml.in/yaml/v3"
	yamlage "sylr.dev/yaml/age/v3"
)

func ExampleWrapper() {
	yamlString := `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`

	rbuf := bytes.NewBufferString(yamlString)
	wbuf := bytes.NewBuffer(nil)

	node := struct {
		Password yamlage.String `yaml:"password"`
	}{}

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	w := yamlage.Wrapper{
		Value:      &node,
		Identities: []age.Identity{id},
	}

	decoder := yaml.NewDecoder(rbuf)
	encoder := yaml.NewEncoder(wbuf)
	encoder.SetIndent(2)

	err = decoder.Decode(&w)

	if err != nil {
		panic(err)
	}

	err = encoder.Encode(&node)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", wbuf.String())
	// Output:
	// password: !crypto/age ThisIsMyReallyEncryptedPassword
}

func ExampleWrapper_anonymous() {
	yamlString := `
password: !crypto/age:DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----
---
password: !crypto/age:SingleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----
---
password: !crypto/age:DoubleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`

	rbuf := bytes.NewBufferString(yamlString)
	wbuf := bytes.NewBuffer(nil)

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	node := &yaml.Node{}

	w := yamlage.Wrapper{
		Value:      node,
		Identities: []age.Identity{id},
	}

	decoder := yaml.NewDecoder(rbuf)
	encoder := yaml.NewEncoder(wbuf)
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

	fmt.Printf("%s", wbuf.String())
	// Output:
	// password: !crypto/age:DoubleQuoted "ThisIsMyReallyEncryptedPassword"
	// ---
	// password: !crypto/age:SingleQuoted 'ThisIsMyReallyEncryptedPassword'
	// ---
	// password: "ThisIsMyReallyEncryptedPassword"
}

func ExampleString_encode() {
	rec, err := age.NewScryptRecipient("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		panic(err)
	}

	node := struct {
		Password yamlage.String `yaml:"password"`
	}{
		Password: yamlage.NewString("ThisIsMyReallyEncryptedPassword", []age.Recipient{rec}),
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
