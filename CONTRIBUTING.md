# Contributing to zerocaptcha-go

Thank you for helping. This repository is a mirror of the ZeroCaptcha SDK for Go, which is developed in ZeroCaptcha's main repository and copied here on every release. Issues and pull requests are welcome here: a maintainer applies an accepted change upstream, and it comes back with the next release.

## Run the tests

You need Go 1.22 or later.

```sh
go test ./...
```

The tests run against a stand-in API on your machine: they need no API key, make no real task and spend nothing. CI runs the same commands on every push and pull request.

## Pull requests

- One change per pull request, with a test when behaviour changes.
- Keep the code small, readable and dependency-light, in the style around it.
- Never commit an API key, a proxy password or an `.env` file. The tests use made-up keys.
- By contributing, you agree that your contribution is licensed under the MIT licence of this repository.

## Issues and support

Open an issue with one of the templates for a bug in this repository or an idea for it. For your account, a task, a payment or anything about the service itself, write to support from the [contact page](https://zerocaptcha.io/contact) and quote the request ID from the error.

## Security

Report a vulnerability privately through [GitHub's private vulnerability reporting](https://github.com/ZeroCaptcha/zerocaptcha-go/security/advisories/new), never in a public issue.
