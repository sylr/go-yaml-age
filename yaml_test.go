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

func TestSimpleDataString(t *testing.T) {
	ids, recs := getKeysFromFiles(t)

	d1 := struct {
		Data ArmoredString `yaml:"data"`
	}{
		Data: ArmoredString{
			Value:      "this is a test",
			Recipients: recs,
		},
	}

	// Marshal
	bytes, err := yaml.Marshal(&d1)

	if err != nil {
		t.Fatal(err)
	}

	str := string(bytes)

	Convey("Check age armor header and footer", t, FailureHalts, func() {
		So(str, ShouldContainSubstring, armor.Header)
		So(str, ShouldContainSubstring, armor.Footer)
	})

	// Unmarshal
	d2 := struct {
		Data string `yaml:"data"`
	}{}

	w := Wrapper{
		Value:      &d2,
		Identities: ids,
	}

	err = yaml.Unmarshal(bytes, &w)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	Convey("Compare orginal struct with result of Unmarshalling", t, func() {
		So(d1.Data.String(), ShouldEqual, d2.Data)
	})
}

func TestSimpleDataArmoredString(t *testing.T) {
	ids, recs := getKeysFromFiles(t)

	d1 := struct {
		Data ArmoredString `yaml:"data"`
	}{
		Data: ArmoredString{
			Recipients: recs,
			Value:      "this is a test",
		},
	}

	// Marshal
	bytes, err := yaml.Marshal(&d1)

	if err != nil {
		t.Fatal(err)
	}

	str := string(bytes)

	Convey("Check age armor header and footer", t, FailureHalts, func() {
		So(str, ShouldContainSubstring, armor.Header)
		So(str, ShouldContainSubstring, armor.Footer)
	})

	// Unmarshal
	d2 := struct {
		Data string `yaml:"data"`
	}{}

	w := Wrapper{
		Value:      &d2,
		Identities: ids,
	}

	err = yaml.Unmarshal(bytes, &w)

	Convey("Compare orginal struct with result of Unmarshalling", t, func() {
		So(err, ShouldBeNil)
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
	RegularData []string        `yaml:"regularData"`
	CryptedData []ArmoredString `yaml:"cryptedData"`
}

func TestComplexData(t *testing.T) {
	// Key files
	idFile, err := os.Open("./testdata/age.key")

	if err != nil {
		t.Fatal(err)
	}

	recFile, err := os.Open("./testdata/age.pub")

	if err != nil {
		t.Fatal(err)
	}

	ids, err := age.ParseIdentities(idFile)

	if err != nil {
		t.Fatal(err)
	}

	recs, err := age.ParseRecipients(recFile)

	if err != nil {
		t.Fatal(err)
	}

	// -- test 1 ---------------------------------------------------------------

	d1 := complexStruct{
		RegularData: []string{
			"this is the first pwet",
			"this is the second pwet",
		},
		CryptedData: []ArmoredString{
			{Value: "this is supposed to be crypted", Recipients: recs},
			{Value: "this is also supposed to be crypted", Recipients: recs},
		},
	}

	out1, err := yaml.Marshal(&d1)

	Convey("Unmarshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for non encrypted data which shouldn't be", t, func() {
		So(err, ShouldBeNil)
		So(string(out1), ShouldContainSubstring, "this is the first pwet")
		So(string(out1), ShouldContainSubstring, "this is the second pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, func() {
		So(err, ShouldBeNil)
		So(string(out1), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(out1), ShouldNotContainSubstring, "this is also supposed to be crypted")
	})

	// -- test 2 ---------------------------------------------------------------

	d2 := yaml.Node{}
	w := Wrapper{Value: &d2, Identities: ids}
	err = yaml.Unmarshal(out1, &w)

	Convey("Unmarshal should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for encrypted data which shouldn't be", t, func() {
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

	out2, err := yaml.Marshal(&d3)

	Convey("Marshalling should not return error", t, FailureHalts, func() {
		So(err, ShouldBeNil)
	})

	Convey("Search for non encrypted data which shouldn't be", t, func() {
		So(err, ShouldBeNil)
		So(string(out2), ShouldContainSubstring, "this is the first pwet")
		So(string(out2), ShouldContainSubstring, "this is the second pwet")
	})

	Convey("Search for non encrypted data which should be encrypted", t, func() {
		So(string(out2), ShouldNotContainSubstring, "this is supposed to be crypted")
		So(string(out2), ShouldNotContainSubstring, "this is also supposed to be crypted")
	})

	Convey("Compare orginal yaml to re-marshalled one, it should differ due to age rekeying", t, func() {
		So(string(out1), ShouldNotEqual, string(out2))
	})

	// -- test 4 ---------------------------------------------------------------

	d4 := complexStruct{}
	w.Value = &d4
	err = yaml.Unmarshal(out1, &w)

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

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

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

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

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

func TestUnlmarshallingMarshallingFormatting(t *testing.T) {
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
	}

	id, err := age.NewScryptIdentity("point-adjust-member-tip-tiger-limb-honey-prefer-copy-issue")

	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		buf := bytes.NewBufferString(test.Input)
		node := yaml.Node{}

		w := Wrapper{
			Value:        &node,
			Identities:   []age.Identity{id},
			DiscardNoTag: test.DiscardNoTag,
		}
		decoder := yaml.NewDecoder(buf)
		err = decoder.Decode(&w)

		Convey(fmt.Sprintf("%s: Decode should not return error", test.Description), t, FailureHalts, func() {
			So(err, ShouldBeNil)
		})

		actual := new(bytes.Buffer)
		encoder := yaml.NewEncoder(actual)
		encoder.SetIndent(2)
		err = encoder.Encode(&node)

		Convey(fmt.Sprintf("%s: Encode should not return error", test.Description), t, FailureHalts, func() {
			So(err, ShouldBeNil)
		})

		Convey(test.Description, t, func() {
			So(actual.String(), test.Assertion, test.Expected)
		})
	}
}
