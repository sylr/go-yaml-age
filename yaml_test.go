package age

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"filippo.io/age"
	"filippo.io/age/armor"
	"sylr.dev/yaml/v3"
)

const (
	passphrase = "point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue"
)

func getKeysFromFiles(t *testing.T) ([]age.Identity, []age.Recipient) {
	// Key files
	idFile, err := os.Open("./testdata/age.key")

	if err != nil {
		t.Fatal(err)
	}

	recFile, err := os.Open("./testdata/age.pub")

	if err != nil {
		t.Fatal(err)
	}

	// Parse key files for identities
	ids, err := age.ParseIdentities(idFile)

	if err != nil {
		t.Fatal(err)
	}

	// Parse key files for recipients
	recs, err := age.ParseRecipients(recFile)

	if err != nil {
		t.Fatal(err)
	}

	return ids, recs
}

func TestSimpleData(t *testing.T) {
	ids, recs := getKeysFromFiles(t)

	// ArmoredStruct based
	d1 := struct {
		Data String `yaml:"data"`
	}{
		Data: NewString("this is a test", recs),
	}

	// Marshal
	d1Bytes, err := yaml.Marshal(&d1)

	Convey("Marshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Check age armor header and footer", t, FailureHalts, func() {
		str := string(d1Bytes)
		So(str, ShouldContainSubstring, armor.Header)
		So(str, ShouldContainSubstring, armor.Footer)
	})

	// String based
	d2 := struct {
		Data string `yaml:"data"`
	}{}

	w := Wrapper{
		Value:      &d2,
		Identities: ids,
	}

	// Populate d2 from d1 marshalling results
	err = yaml.Unmarshal(d1Bytes, &w)

	Convey("Unmarshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Compare Unmarshalling outputs", t, func() {
		So(d1.Data.String(), ShouldEqual, d2.Data)
	})
}

func TestAnonymousStruct(t *testing.T) {
	ids, _ := getKeysFromFiles(t)

	// Open source yaml
	yamlFile, err := os.Open("./testdata/lipsum.yaml")

	if err != nil {
		t.Fatal(err)
	}

	// "anonymous" struct
	d1 := make(map[interface{}]interface{})

	// Decode
	w := Wrapper{Value: &d1, Identities: ids}
	decoder := yaml.NewDecoder(yamlFile)
	err = decoder.Decode(&w)

	Convey("Decoding should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	// Check that the decoded yaml has the lipsum key
	if _, ok := d1["lipsum"]; !ok {
		t.Errorf("Decoded yaml has no lipsum key")
		t.FailNow()
	}

	// Open the file containing the original data used in the yaml file
	lipsumFile, err := os.Open("./testdata/lipsum.txt")

	if err != nil {
		t.Fatal(err)
	}

	lipsumBuf, err := ioutil.ReadAll(lipsumFile)

	if err != nil {
		t.Fatal(err)
	}

	lipsum := string(lipsumBuf)

	Convey("Compare orginal lipsum to decoded one", t, func() {
		So(d1["lipsum"], ShouldEqual, lipsum)
	})
}

type complexStruct struct {
	RegularData []string `yaml:"regularData"`
	CryptedData []String `yaml:"cryptedData"`
}

func TestComplexData(t *testing.T) {
	ids, recs := getKeysFromFiles(t)

	// -- test 1 ---------------------------------------------------------------

	d1 := complexStruct{
		RegularData: []string{
			"this is the first pwet",
			"this is the second pwet",
		},
		CryptedData: []String{
			NewString("this is supposed to be crypted", recs),
			NewString("this is also supposed to be crypted", recs),
		},
	}

	d1Bytes, err := yaml.Marshal(&d1)
	fmt.Println(string(d1Bytes))

	Convey("Unmarshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for non encrypted data which shouldn't be", t, FailureHalts, func() {
		So(err, ShouldBeNil)
		So(string(d1Bytes), ShouldContainSubstring, "this is the first pwet")
		So(string(d1Bytes), ShouldContainSubstring, "this is the second pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, FailureHalts, func() {
		So(err, ShouldBeNil)
		So(string(d1Bytes), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(d1Bytes), ShouldNotContainSubstring, "this is also supposed to be crypted")
	})

	// -- test 2 ---------------------------------------------------------------

	d2 := yaml.Node{}
	w := Wrapper{Value: &d2, Identities: ids}
	err = yaml.Unmarshal(d1Bytes, &w)

	Convey("Unmarshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for encrypted data which shouldn't be", t, FailureHalts, func() {
		var recurse func(node *yaml.Node)
		recurse = func(node *yaml.Node) {
			if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
				if len(node.Content) > 0 {
					for i := range node.Content {
						recurse(node.Content[i])
					}
				}
			}

			So(node.Value, ShouldNotContainSubstring, armor.Header)
			So(node.Value, ShouldNotContainSubstring, armor.Footer)
		}
		recurse(&d2)
	})

	// -- test 3 ---------------------------------------------------------------

	d3, err := MarshalYAML(&d2, recs)

	Convey("MarshalYAML should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	d3bytes, err := yaml.Marshal(&d3)

	Convey("Marshalling should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for non encrypted data which shouldn't be", t, func() {
		So(err, ShouldBeNil)
		So(string(d3bytes), ShouldContainSubstring, "this is the first pwet")
		So(string(d3bytes), ShouldContainSubstring, "this is the second pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, func() {
		So(string(d3bytes), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(d3bytes), ShouldNotContainSubstring, "this is also supposed to be crypted")
	})

	Convey("Compare orginal yaml to re-marshalled one, it should differ due to age rekeying", t, func() {
		So(string(d1Bytes), ShouldNotEqual, string(d3bytes))
	})

	// -- test 4 ---------------------------------------------------------------

	d4 := complexStruct{}
	w.Value = &d4
	err = yaml.Unmarshal(d1Bytes, &w)

	Convey("Unmarshalling should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for non encrypted data which should be", t, func() {
		So(d4.RegularData[0], ShouldContainSubstring, "this is the first pwet")
		So(d4.RegularData[1], ShouldContainSubstring, "this is the second pwet")
	})

	Convey("Search for encrypted data which shouldn't be", t, func() {
		So(d4.CryptedData[0].String(), ShouldContainSubstring, "this is supposed to be crypted")
		So(d4.CryptedData[1].String(), ShouldContainSubstring, "this is also supposed to be crypted")
	})
}

func TestUnlmarshallingInputDocument(t *testing.T) {
	tests := []struct {
		Description string
		Assertion   func(interface{}, ...interface{}) string
		Input       string
	}{
		{
			Description: "Bogus age payload: bogus base64",
			Assertion:   ShouldBeNil,
			Input: `
password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----
---
password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----
`,
		},
	}

	id, err := age.NewScryptIdentity(passphrase)

	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		buf := bytes.NewBufferString(test.Input)
		node := yaml.Node{}

		w := Wrapper{
			Value:      &node,
			Identities: []age.Identity{id},
		}
		decoder := yaml.NewDecoder(buf)

		for {
			err = decoder.Decode(&w)
			if err == io.EOF {
				break
			} else {
				Convey(test.Description, t, func() {
					So(err, test.Assertion)
				})
			}

			out, _ := yaml.Marshal(&node)
			fmt.Println("---\n" + string(out) + "\n")
		}
	}
}

func TestUnlmarshallingBogusEncryptedData(t *testing.T) {
	tests := []struct {
		Description string
		Assertion   func(interface{}, ...interface{}) string
		Input       string
	}{
		{
			Description: "Bogus age payload: bogus base64",
			Assertion:   ShouldBeError,
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBvTDRrOUlXRGFYcXkzaVZu
  WXpzZndRzIDE4ClZ3YVVHb0lVWlJtblVFazU4TlBkTitCWlg3dUNqd2N6R0hGVUFr
  T2gwb2sKLS0tIGFPYXBybWRUelNKeWkzc1lrVGpXUHJ4dDI4bWFDZEl6OXhpeTNY
  N0lIVjgKxPtRljkraTILjhf3v0MM5GmKnBwOMqLu2030RWMl6iW7YEYvunx2AMUA
  grTyTgUElzo=....
  -----END AGE ENCRYPTED FILE-----
`,
		},
		{
			Description: "Bogus age payload: no base64",
			Assertion:   ShouldBeError,
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  ...
  -----END AGE ENCRYPTED FILE-----
`,
		},
		{
			Description: "Bogus age payload: base64 not age data",
			Assertion:   ShouldBeError,
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  cWtsc2RobGtxZGhqc2ts
  -----END AGE ENCRYPTED FILE-----
`,
		},
		{
			Description: "Not encrypted payload",
			Assertion:   ShouldBeNil,
			Input: `password: !crypto/age |
  this is a test
`,
		},
		{
			Description: "Several style defined",
			Assertion:   ShouldBeError,
			Input: `password: !crypto/age:SingleQuoted,DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
		},
		{
			Description: "Unknown attribute",
			Assertion:   ShouldBeError,
			Input: `password: !crypto/age:Pwet |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
		},
	}

	id, err := age.NewScryptIdentity(passphrase)

	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		buf := bytes.NewBufferString(test.Input)
		node := yaml.Node{}

		w := Wrapper{
			Value:      &node,
			Identities: []age.Identity{id},
		}
		decoder := yaml.NewDecoder(buf)
		err = decoder.Decode(&w)

		Convey(test.Description, t, func() {
			So(err, test.Assertion)
		})
	}
}

func TestNoRecipientMarshal(t *testing.T) {
	d1 := complexStruct{
		RegularData: []string{
			"this is the first pwet",
			"this is the second pwet",
		},
		CryptedData: []String{
			NewString("this is supposed to be crypted", []age.Recipient{&age.X25519Recipient{}}),
			NewString("this is also supposed to be crypted", []age.Recipient{&age.X25519Recipient{}}),
		},
	}

	out := new(bytes.Buffer)
	encoder := yaml.NewEncoder(out)
	encoder.SetIndent(2)
	err := encoder.Encode(d1)

	Convey("Encode should return error", t, FailureHalts, func() {
		So(err, ShouldBeError)
	})
}

func TestDecodeEncodeMarshal(t *testing.T) {
	tests := []struct {
		Description  string
		Assertion    func(interface{}, ...interface{}) string
		Input        string
		Expected     string
		DiscardNoTag bool
	}{
		{
			Description: "Not style defined",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Double quoted",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:DoubleQuoted "ThisIsMyReallyEncryptedPassword"`),
		},
		{
			Description: "Single quoted",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:SingleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:SingleQuoted 'ThisIsMyReallyEncryptedPassword'`),
		},
		{
			Description: "Literal",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Literal |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Literal |-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Folded",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Folded |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Folded >-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Flow",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Flow |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Flow ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "No tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Double quoted, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:DoubleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: "ThisIsMyReallyEncryptedPassword"`),
		},
		{
			Description: "Single quoted, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:SingleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: 'ThisIsMyReallyEncryptedPassword'`),
		},
		{
			Description: "Literal, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Literal,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: |-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Folded, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Folded,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: >-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Flow, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Flow,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Flow, No Tag, DiscardNoTag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Flow,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----`,
			Expected:     fmt.Sprintln(`password: !crypto/age:Flow,NoTag ThisIsMyReallyEncryptedPassword`),
			DiscardNoTag: true,
		},
		{
			Description: "Anchor",
			Assertion:   ShouldEqual,
			Input: `password: &passwd !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
  cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
  MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
  Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
  8zlxcVRSeplPrnuRdOUBgjoNtdUt
  -----END AGE ENCRYPTED FILE-----
dup: *passwd`,
			Expected: fmt.Sprintln(`password: &passwd !crypto/age ThisIsMyReallyEncryptedPassword
dup: *passwd`),
			DiscardNoTag: false,
		},
		{
			Description: "Comment",
			Assertion:   ShouldEqual,
			Input: `head:
  # this is a head comment
  password: &passwd !crypto/age | # this is a line comment
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4c3VtbURKYlhNclZORExq
    cVdyM1RnIDE4ClJ3ejBxU292WGJpQWtLQ1NXMnN4THk5VWQvLzVzKzBmWTQvOVp5
    MTQrak0KLS0tIFI1U1RnZXFDVU5YbGJTU3lpNnBOdEVybDdtQmUrM1VkcHV4OElN
    Zm1aZ1kKvhgBDqN8umSS+EmwRwAKj9wNicvbWuynN7W0wxu6apXn57icXGgxiFK0
    8zlxcVRSeplPrnuRdOUBgjoNtdUt
    -----END AGE ENCRYPTED FILE-----
  # this is a footer comment
dup: *passwd`,
			Expected: fmt.Sprintln(`head:
  # this is a head comment
  password: &passwd !crypto/age ThisIsMyReallyEncryptedPassword # this is a line comment
  # this is a footer comment
dup: *passwd`),
			DiscardNoTag: false,
		},
	}

	id, err := age.NewScryptIdentity(passphrase)

	if err != nil {
		t.Fatal(err)
	}

	rec, err := age.NewScryptRecipient(passphrase)

	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		input := test.Input
		for i := 1; i < 3; i++ {
			buf := bytes.NewBufferString(input)
			node := yaml.Node{}

			w := Wrapper{
				Value:        &node,
				Identities:   []age.Identity{id},
				DiscardNoTag: test.DiscardNoTag,
			}

			actual := new(bytes.Buffer)
			decoder := yaml.NewDecoder(buf)
			encoder := yaml.NewEncoder(actual)
			encoder.SetIndent(2)

			// Load YAML
			err = decoder.Decode(&w)

			Convey(fmt.Sprintf("%s (pass #%d): Decode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			// Marshall decrypted values
			err = encoder.Encode(&node)

			Convey(fmt.Sprintf("%s (pass #%d): Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			Convey(fmt.Sprintf("%s (pass #%d): compare outputs", test.Description, i), t, func() {
				So(actual.String(), test.Assertion, test.Expected)
			})

			// Marshall encrypted values
			_, err := MarshalYAML(&node, []age.Recipient{rec})

			Convey(fmt.Sprintf("%s (pass #%d): MarshalYAML should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			reencoded := new(bytes.Buffer)
			reencoder := yaml.NewEncoder(reencoded)
			err = reencoder.Encode(&node)

			Convey(fmt.Sprintf("%s (pass #%d): Re-Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			input = reencoded.String()
		}
	}
}
