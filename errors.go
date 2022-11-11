package age

import "fmt"

var (
	ErrUnknownAttribute          = fmt.Errorf("unknown attribute")
	ErrMoreThanOneStyleAttribute = fmt.Errorf("can't use more than one style attribute")
	ErrUpstreamAgeError          = fmt.Errorf("age")
	ErrUnsupportedValueType      = fmt.Errorf("unsupported Value type")
)
