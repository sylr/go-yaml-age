package age

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
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
			"this is the third\nand multi-lines pwet",
		},
		CryptedData: []String{
			NewString("this is supposed to be crypted", recs),
			NewString("this is also supposed to be crypted", recs),
			NewString("this is multi-lines\nand also supposed to be crypted", recs),
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
		So(string(d1Bytes), ShouldContainSubstring, "this is the third\n")
		So(string(d1Bytes), ShouldContainSubstring, "and multi-lines pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, FailureHalts, func() {
		So(err, ShouldBeNil)
		So(string(d1Bytes), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(d1Bytes), ShouldNotContainSubstring, "this is also supposed to be crypted")
		So(string(d1Bytes), ShouldNotContainSubstring, "this is multi-lines\n")
		So(string(d1Bytes), ShouldNotContainSubstring, "and also supposed to be crypted")
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
		So(string(d3bytes), ShouldContainSubstring, "this is the third\n")
		So(string(d3bytes), ShouldContainSubstring, "and multi-lines pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, func() {
		So(string(d3bytes), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(d3bytes), ShouldNotContainSubstring, "this is also supposed to be crypted")
		So(string(d3bytes), ShouldNotContainSubstring, "this is multi-lines\n")
		So(string(d3bytes), ShouldNotContainSubstring, "and also supposed to be crypted")
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
		So(d4.RegularData[2], ShouldContainSubstring, "this is the third\nand multi-lines pwet")
	})

	Convey("Search for encrypted data which shouldn't be", t, func() {
		So(d4.CryptedData[0].String(), ShouldContainSubstring, "this is supposed to be crypted")
		So(d4.CryptedData[1].String(), ShouldContainSubstring, "this is also supposed to be crypted")
		So(d4.CryptedData[2].String(), ShouldNotContainSubstring, "this is also supposed to be crypted\nand multi-lines")
	})
}

func TestUnlmarshallingInputDocument(t *testing.T) {
	tests := []struct {
		Description string
		Assertion   func(interface{}, ...interface{}) string
		Input       string
		Expected    string
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
  -----END AGE ENCRYPTED FILE-----`,
			Expected: `password: !crypto/age ThisIsMyReallyEncryptedPassword
---
password: !crypto/age ThisIsMyReallyEncryptedPassword
`,
		},
	}

	id, err := age.NewScryptIdentity(passphrase)

	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		buf := bytes.NewBufferString(test.Input)
		actual := bytes.NewBuffer(nil)
		node := yaml.Node{}

		w := Wrapper{
			Value:      &node,
			Identities: []age.Identity{id},
		}
		decoder := yaml.NewDecoder(buf)
		encoder := yaml.NewEncoder(actual)

		for {
			err = decoder.Decode(&w)
			if err == io.EOF {
				break
			} else {
				Convey(test.Description, t, func() {
					So(err, test.Assertion)
				})
			}

			err := encoder.Encode(&node)
			Convey(test.Description, t, func() {
				So(err, ShouldBeNil)
			})
		}

		Convey(test.Description, t, func() {
			So(actual.String(), ShouldEqual, test.Expected)
		})
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
			Description: "Several styles defined",
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

func TestNoReencrypt(t *testing.T) {
	input := `
foo: !crypto/age bar
baz: plain text
`
	identities, recipients := getKeysFromFiles(t)
	var node yaml.Node

	decoder := yaml.NewDecoder(bytes.NewBufferString(input))
	err := decoder.Decode(&Wrapper{
		Value: &node,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := MarshalYAML(&node, recipients)
	if err != nil {
		t.Fatal(err)
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	decoded := string(b)
	input = fmt.Sprintf("%s\nqux: !crypto/age quux", b)
	decoder = yaml.NewDecoder(bytes.NewBufferString(input))
	node = yaml.Node{}
	err = decoder.Decode(&Wrapper{
		Value:     &node,
		NoDecrypt: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	options := []MarshalYAMLOption{NoReencrypt()}
	n, err = MarshalYAML(&node, recipients, options...)
	if err != nil {
		t.Fatal(err)
	}
	b, err = yaml.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), decoded) {
		t.Fatalf("expected %s to start with %s", string(b), decoded)
	}
	wantPrefix := "qux: !crypto/age |-\n    -----BEGIN AGE ENCRYPTED FILE-----"
	if !strings.HasPrefix(strings.TrimPrefix(string(b), decoded), wantPrefix) {
		t.Fatalf("expected %s to start with %s", strings.TrimPrefix(string(b), decoded), wantPrefix)
	}
	node = yaml.Node{}
	err = yaml.Unmarshal(b, &Wrapper{
		Value:      &node,
		Identities: identities,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoder = yaml.NewDecoder(bytes.NewBuffer(b))
	err = decoder.Decode(&Wrapper{
		Value:      &node,
		Identities: identities,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	encoder := yaml.NewEncoder(out)
	err = encoder.Encode(&node)
	if err != nil {
		t.Fatal(err)
	}
	err = encoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := `foo: !crypto/age bar
baz: plain text
qux: !crypto/age quux
`
	if out.String() != want {
		t.Fatalf("expected %s to equal %s", out.String(), want)
	}
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
			Description: "No style defined",
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
		{
			Description: "Multi-lines",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age |-
  This
  Is
  My
  Really
  Encrypted
  And
  Multilines
  Password`),
			DiscardNoTag: false,
		},
		{
			Description: "Multi-lines, Double Quoted",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected:     fmt.Sprintln(`password: !crypto/age:DoubleQuoted "This\nIs\nMy\nReally\nEncrypted\nAnd\nMultilines\nPassword"`),
			DiscardNoTag: false,
		},
		{
			Description: "Multi-lines, Double Quoted, No Tag",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:DoubleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected:     fmt.Sprintln(`password: "This\nIs\nMy\nReally\nEncrypted\nAnd\nMultilines\nPassword"`),
			DiscardNoTag: false,
		},
		{
			Description: "Multi-lines, Literal",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Literal |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Literal |-
  This
  Is
  My
  Really
  Encrypted
  And
  Multilines
  Password`),
			DiscardNoTag: false,
		},
		{
			Description: "Multi-lines, Folded",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Folded |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Folded >-
  This

  Is

  My

  Really

  Encrypted

  And

  Multilines

  Password`),
			DiscardNoTag: false,
		},
		{
			Description: "Multi-lines, Flow",
			Assertion:   ShouldEqual,
			Input: `password: !crypto/age:Flow |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBGek45eXVhaTFXVHo2Sm5P
  amVzMEJRIDE4CkxpVDU2Z2R3bXFhYjNyRGcwRTFUYmxXTUt6WWhObTk0N0ovWlls
  OXBIK1UKLS0tIDZySlVPekJzOVRvUXhpNlNDc1I4TnNKdVVsU2h0THpoOTFNejNY
  OVBkc1kK10MLHpdxC/BBHvWw2v2MD8PII1zSWrK1YE4V9HgCkkwwBvgxLk2aAcIG
  jApnU5I8D42BUa9lsQiDAG1yXLRrAyFv4WbPyAVzoSUWh7EDbaz1hTU=
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Flow |-
  This
  Is
  My
  Really
  Encrypted
  And
  Multilines
  Password`),
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

			// try again ignoring encrypted values and make sure we get the same result

			buf = bytes.NewBufferString(input)
			node = yaml.Node{}

			w = Wrapper{
				Value:        &node,
				DiscardNoTag: test.DiscardNoTag,
				NoDecrypt:    true,
			}

			actual = new(bytes.Buffer)
			decoder = yaml.NewDecoder(buf)
			encoder = yaml.NewEncoder(actual)
			encoder.SetIndent(2)

			// Load YAML
			err = decoder.Decode(&w)

			Convey(fmt.Sprintf("%s (pass #%d): Decode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			err = encoder.Encode(&node)

			Convey(fmt.Sprintf("%s (pass #%d): Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			_, err = MarshalYAML(&node, []age.Recipient{rec}, NoReencrypt())

			Convey(fmt.Sprintf("%s (pass #%d): MarshalYAML should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			reencoded = new(bytes.Buffer)
			reencoder = yaml.NewEncoder(reencoded)
			err = reencoder.Encode(&node)

			Convey(fmt.Sprintf("%s (pass #%d): Re-Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			Convey(fmt.Sprintf("%s (pass #%d): Re-Encode should match original", test.Description, i), t, FailureHalts, func() {
				So(reencoded.String(), ShouldEqual, input)
			})
		}
	}
}

// TestIncorrectBehaviours defines a series of tests that produce known incorrect
// behaviours that should be fixed
func TestIncorrectBehaviours(t *testing.T) {
	tests := []struct {
		Description  string
		Assertion    func(interface{}, ...interface{}) string
		Input        string
		Expected     string
		DiscardNoTag bool
	}{
		{
			Description: "Boolean",
			Assertion:   ShouldEqual,
			Input:       `password: !crypto/age:NoTag true`,
			Expected:    `password: "true"` + "\n",
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

			// Load YAML
			decoder := yaml.NewDecoder(buf)
			err = decoder.Decode(&w)

			Convey(fmt.Sprintf("%s (pass #%d): Decode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			// Encrypt decrypted values
			mnode, err := MarshalYAML(&node, []age.Recipient{rec})

			Convey(fmt.Sprintf("%s (pass #%d): Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			// Marshal
			actual := new(bytes.Buffer)
			encoder := yaml.NewEncoder(actual)
			encoder.SetIndent(2)
			err = encoder.Encode(mnode)

			Convey(fmt.Sprintf("%s (pass #%d): Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			// Re-decode
			rebuf := bytes.NewBuffer(actual.Bytes())
			renode := yaml.Node{}

			rew := Wrapper{
				Value:        &renode,
				Identities:   []age.Identity{id},
				DiscardNoTag: test.DiscardNoTag,
			}

			redecoder := yaml.NewDecoder(rebuf)
			err = redecoder.Decode(&rew)

			Convey(fmt.Sprintf("%s (pass #%d): Re-Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			// Re-marshal
			reencoded := new(bytes.Buffer)
			reencoder := yaml.NewEncoder(reencoded)
			reencoder.SetIndent(2)

			err = reencoder.Encode(&renode)

			Convey(fmt.Sprintf("%s (pass #%d): Re-Encode should not return error", test.Description, i), t, FailureHalts, func() {
				So(err, ShouldBeNil)
			})

			Convey(fmt.Sprintf("%s (pass #%d): compare outputs", test.Description, i), t, func() {
				So(reencoded.String(), test.Assertion, test.Expected)
			})

			input = reencoded.String()
		}
	}
}
