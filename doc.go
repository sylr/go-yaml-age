// Package age provides a wrapper for `sylr.dev/yaml/v3` which allows to
// encrypt/decrypt YAML values in place using AGE.
//
// It only supports encrypting/decrypting strings, it will treat any other YAML
// type like bool, int, float ... etc as strings.
package age
