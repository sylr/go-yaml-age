module sylr.dev/yaml/age/v3

go 1.15

require (
	filippo.io/age v1.0.0-beta5
	github.com/smartystreets/goconvey v1.6.4
	golang.org/x/crypto v0.0.0-20201208171446-5f87f3452ae9 // indirect
	golang.org/x/sys v0.0.0-20201211090839-8ad439b19e0f // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
)

replace (
	filippo.io/age => github.com/sylr/age v1.0.0-beta5.0.20201126225131-a495df083bec
	gopkg.in/yaml.v3 => github.com/sylr/go-yaml v0.0.0-20201211202443-be0157e6a8ed
)
