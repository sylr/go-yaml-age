go-yaml-age
===========

[![pkg.go.dev](https://pkg.go.dev/badge/sylr.dev/yaml/age/v3)](https://pkg.go.dev/sylr.dev/yaml/age/v3)
[![codecov](https://codecov.io/gh/sylr/go-yaml-age/branch/master/graph/badge.svg?token=5WDCMLDFA7)](https://codecov.io/gh/sylr/go-yaml-age)

Wrapper for [`go.yaml.in/yaml/v3`](https://pkg.go.dev/go.yaml.in/yaml/v3) which allows
to encrypt/decrypt YAML data in place using the [`AGE`](https://age-encryption.org/v1) encryption tool.

Documentation
-------------

You'll find the documentation and examples on [`pkg.go.dev`](https://pkg.go.dev/sylr.dev/yaml/age/v3).

Applications
------------

This wrapper has been written in order to bring YAML support to [@FiloSottile](https://github.com/FiloSottile)'s
[`age`](https://github.com/FiloSottile/age) cli implementation.

The ultimate goals are to provide AGE support in [`kustomize`](https://github.com/kubernetes-sigs/kustomize/)
and [@fluxcd](https://github.com/fluxcd)'s [`kustomize-controller`](https://github.com/fluxcd/kustomize-controller).

You can find unofficial binaries of `age` and `kustomize` with AGE support at https://github.com/sylr/kustomize-age.
