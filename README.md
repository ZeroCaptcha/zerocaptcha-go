<!-- zc:header (generated from the registry; edit repos/registry.json) -->
# ZeroCaptcha SDK for Go

[![CI](https://github.com/ZeroCaptcha/zerocaptcha-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ZeroCaptcha/zerocaptcha-go/actions/workflows/ci.yml)

The official ZeroCaptcha client for Go: solve Cloudflare Turnstile and Cloudflare challenge pages, wait for results, read the balance and verify callback signatures. Standard library only, Go 1.22+, context-aware.

[Website](https://zerocaptcha.io/docs/sdks/go) · [Docs](https://zerocaptcha.io/docs) · [Quickstart](https://zerocaptcha.io/docs/quickstart) · [API reference](https://zerocaptcha.io/docs/reference/api) · [Pricing](https://zerocaptcha.io/pricing)
<!-- /zc:header -->

## What it does

`github.com/zerocaptcha/zerocaptcha-go` is the official ZeroCaptcha client for Go. It creates a Cloudflare Turnstile task or a Cloudflare challenge page's task, waits for the result, reads your balance, and checks a task callback's signature. It uses the standard library only, needs Go 1.22 or later, and stops each call when its context does.

Every task is real and paid from your prepaid balance, and only a task that succeeds is charged.

## Install

```sh
go get github.com/zerocaptcha/zerocaptcha-go
```

<!-- zc:include sdks/go/README.md sections="Use|Cloudflare challenge pages|Callbacks" -->
## Use

Give the client your API key (`zc_live_…`, from the dashboard's API keys page) and the API's
address, `https://api.zerocaptcha.io`, which is also its default when the address is empty. Keep
both in your environment rather than in your code.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	zerocaptcha "github.com/zerocaptcha/zerocaptcha-go"
)

func main() {
	client, err := zerocaptcha.NewClient(os.Getenv("ZEROCAPTCHA_KEY"), os.Getenv("ZEROCAPTCHA_API"))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// Create a task and wait for its token: one call.
	token, err := client.Solve(ctx, zerocaptcha.NewTask{
		WebsiteURL: "https://shop.example.com/login", // the page with the widget
		WebsiteKey: "0x4AAAAAAAB1cD2eF3gH4iJ5",       // its data-sitekey
		// The widget's data-action and data-cdata, or the action and cData options of
		// turnstile.render(). Leave out any the widget does not set.
		Action: "login",
		CData:  "session-7f3a9c2e",
		// Proxy:       "http://user:pass@proxy.example.net:8080", // to solve through your own proxy
		// CallbackURL: "https://hooks.example.com/zerocaptcha",   // to be called when it ends
	})
	var failed *zerocaptcha.TaskFailedError
	switch {
	case errors.As(err, &failed):
		fmt.Println(failed.Code) // such as ERROR_CAPTCHA_UNSOLVABLE; nothing was charged
	case err != nil:
		log.Fatal(err)
	default:
		fmt.Println(token)
	}

	// Or step by step.
	task, err := client.CreateTask(ctx, zerocaptcha.NewTask{
		WebsiteURL: "https://shop.example.com/login",
		WebsiteKey: "0x4AAAAAAAB1cD2eF3gH4iJ5",
		Action:     "login",            // the widget's data-action, if it sets one
		CData:      "session-7f3a9c2e", // the widget's data-cdata, if it sets one
	}, zerocaptcha.CreateOptions{
		// Your ID for this task, sent as the Idempotency-Key; one is made for you when you give none.
		IdempotencyKey: "login-2026-10-01-0001",
	})
	if err != nil {
		log.Fatal(err)
	}
	done, err := client.WaitForResult(ctx, task.ID, zerocaptcha.WaitOptions{Timeout: 2 * time.Minute})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(done.Solution.Token, done.Cost)

	// Your balance, in US dollars.
	balance, err := client.GetBalance(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balance.Available)
}
```

- `Proxy: "http://user:pass@proxy.example.net:8080"` solves a task through your proxy.
- `CreateTask` sends an `Idempotency-Key` with every call, one of its own unless you give one in
  `CreateOptions`, so retrying it never makes a second task.
- A request the API asks you to slow down (429) or cannot serve for a moment (502, 503, 504) is
  tried again after the wait it asks for, three times in all, as is one that got no answer or an
  answer cut short, with the same `Idempotency-Key`. Any other refusal is an `*APIError` with the
  API's `Code`, such as `insufficient_funds`, and its `RequestID`.
- `WaitForResult` asks every 2 seconds for up to 3 minutes, and never runs past its `Timeout`:
  each read gets only the time left, and a retry that would wait longer than that is not made. A
  task that fails or expires is a `*TaskFailedError`; a wait that runs out is a
  `*WaitTimeoutError`, with the task as last read (`Task`, nil if no read finished in time), and
  you can wait again. Each call stops when its context does.

## Cloudflare challenge pages

A challenge page ("Just a moment…") is passed through your proxy, and gives the `cf_clearance`
cookie with the user agent it is bound to. Send both, through the same proxy:

```go
clearance, err := client.SolveChallenge(ctx, zerocaptcha.NewChallengeTask{
	WebsiteURL: "https://shop.example.com/",
	Proxy:      os.Getenv("PROXY_URL"), // such as http://user:pass@proxy.example.net:8080
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(clearance.CfClearance, clearance.UserAgent)
```

`CreateChallengeTask` creates the task alone, for `WaitForResult`. A challenge task always needs a
proxy: a clearance works only from the address that earned it.

## Callbacks

A task created with `CallbackURL` is POSTed to it once it ends, with the task as JSON. Each call
carries `ZeroCaptcha-Signature: t=<unix seconds>,v1=<hex>`, the HMAC-SHA256 of `<t>.<body>` under
your callback secret (`zcsig_…`, on the dashboard's API keys page, for owners). Check it against
the raw body, before you parse it:

```go
body, _ := io.ReadAll(r.Body)
if !zerocaptcha.VerifySignature(secret, r.Header.Get(zerocaptcha.SignatureHeader), body, 0, time.Time{}) {
	http.Error(w, "bad signature", http.StatusUnauthorized)
	return
}
```

A call older than five minutes does not verify, so a recorded call cannot be replayed. Answer 2xx
once you have it; any other answer is retried with backoff, eight attempts in all over
roughly 65 to 95 minutes.
<!-- /zc:include -->

## FAQ

**Which API does it call?**
ZeroCaptcha's REST API: `POST /v1/tasks`, `GET /v1/tasks/{id}` and `GET /v1/balance`. The [API reference](https://zerocaptcha.io/docs/reference/api) documents every field and error.

**Is the client safe to share between goroutines?**
Yes: create one and share it.

**Does it work with colly?**
Yes: solve, then send the token or the clearance with colly's requests. The [Go colly tutorial](https://zerocaptcha.io/blog/go-colly-cloudflare-turnstile) shows it.

**What does a solve cost?**
The [pricing page](https://zerocaptcha.io/pricing) lists the price per 1,000 solved tasks. Only a task that succeeds is charged.

## Develop

```sh
go vet ./...
go test ./...   # against a stand-in API on your machine
```

This repository is a mirror of the SDK as it is developed in ZeroCaptcha's main repository, copied here on every release. Issues and pull requests are welcome here; an accepted change is made upstream and comes back with the next release.

<!-- zc:footer (generated from the registry) -->
## More from ZeroCaptcha

- The website: [ZeroCaptcha](https://zerocaptcha.io), the [docs](https://zerocaptcha.io/docs), the [guides](https://zerocaptcha.io/guides), the [blog](https://zerocaptcha.io/blog) and the [status page](https://zerocaptcha.io/status)
- Start here: [zerocaptcha](https://github.com/ZeroCaptcha/zerocaptcha), [cloudflare-turnstile-solver](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver), [cloudflare-challenge-solver](https://github.com/ZeroCaptcha/cloudflare-challenge-solver)
- Examples by language: [cloudflare-turnstile-solver-python](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-python), [cloudflare-turnstile-solver-nodejs](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-nodejs), [cloudflare-turnstile-solver-go](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-go), [cloudflare-turnstile-solver-php](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-php), [cloudflare-turnstile-solver-java](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-java), [cloudflare-turnstile-solver-csharp](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-csharp), [cloudflare-turnstile-solver-rust](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-rust)
- Browser automation: [cloudflare-turnstile-solver-playwright](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-playwright), [cloudflare-turnstile-solver-puppeteer](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-puppeteer), [cloudflare-turnstile-solver-selenium](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-selenium)
- SDKs, MCP server and migration: [zerocaptcha-js](https://github.com/ZeroCaptcha/zerocaptcha-js), [zerocaptcha-python](https://github.com/ZeroCaptcha/zerocaptcha-python), **zerocaptcha-go**, [zerocaptcha-mcp](https://github.com/ZeroCaptcha/zerocaptcha-mcp), [createtask-api-migration](https://github.com/ZeroCaptcha/createtask-api-migration)
- Lists: [awesome-cloudflare-turnstile](https://github.com/ZeroCaptcha/awesome-cloudflare-turnstile)

## Licence

MIT: see [LICENSE](LICENSE).

## Disclaimer

ZeroCaptcha is an independent service, not affiliated with or endorsed by Cloudflare. Cloudflare and Turnstile are trademarks of Cloudflare, Inc. Use ZeroCaptcha only on sites you own or are allowed to automate, as the [Acceptable Use Policy](https://zerocaptcha.io/legal/acceptable-use) says; any site owner can [opt out](https://zerocaptcha.io/opt-out).
<!-- /zc:footer -->
