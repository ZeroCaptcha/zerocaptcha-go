package zerocaptcha

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const key = "zc_live_StandInKeyForTheSdkTests0123456789a"

// seen is a request the stand-in saw.
type seen struct {
	method, path string
	header       http.Header
	body         map[string]any
}

type refusal struct {
	status     int
	code       string
	retryAfter string
}

// standIn answers as the REST API does, from a script of statuses per task, and records requests.
type standIn struct {
	mu       sync.Mutex
	seen     []seen
	script   map[string][]string
	tasks    map[string]Task
	byKey    map[string]string
	refusals []refusal
	next     int
	server   *httptest.Server
	// readDelay is how long each read of a task takes to answer.
	readDelay time.Duration
	// cutBodies is how many task creations, made in full, to answer with a body cut short.
	cutBodies int
}

var taskPath = regexp.MustCompile(`^/v1/tasks/([^/]+)$`)

func newStandIn(t *testing.T) *standIn {
	api := &standIn{script: map[string][]string{}, tasks: map[string]Task{}, byKey: map[string]string{}}
	api.server = httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(api.server.Close)
	return api
}

func (api *standIn) handle(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	api.seen = append(api.seen, seen{r.Method, r.URL.Path, r.Header.Clone(), body})
	send := func(status int, value any) {
		if status >= 400 {
			w.Header().Set("Content-Type", "application/problem+json")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	refuse := func(status int, code string) {
		send(status, map[string]any{
			"type": "about:blank", "title": code, "status": status, "code": code,
			"detail": "Refused: " + code + ".", "request_id": "req-1",
		})
	}
	if r.Header.Get("Authorization") != "Bearer "+key {
		refuse(http.StatusUnauthorized, "unauthorized")
		return
	}
	if len(api.refusals) > 0 {
		next := api.refusals[0]
		api.refusals = api.refusals[1:]
		if next.retryAfter != "" {
			w.Header().Set("Retry-After", next.retryAfter)
		}
		refuse(next.status, next.code)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/tasks" {
		idempotency := r.Header.Get("Idempotency-Key")
		if id, ok := api.byKey[idempotency]; ok {
			send(http.StatusCreated, api.tasks[id])
			return
		}
		api.next++
		id := fmt.Sprintf("0192f3a4-7b1c-7d2e-9f10-00000000000%d", api.next)
		task := Task{
			ID: id, Type: fmt.Sprint(body["type"]), Status: "queued",
			WebsiteURL: fmt.Sprint(body["websiteURL"]), WebsiteKey: fmt.Sprint(body["websiteKey"]),
			Price: "0.000800", Held: "0.000800", Cost: "0.000000", CreatedAt: "2026-09-30T10:00:00Z",
		}
		api.tasks[id] = task
		api.byKey[idempotency] = id
		if api.cutBodies > 0 {
			// The task is made; its answer stops halfway, and the connection drops.
			api.cutBodies--
			whole, _ := json.Marshal(task)
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(buffered, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(whole), whole[:20])
			_ = buffered.Flush()
			_ = conn.Close()
			return
		}
		send(http.StatusCreated, task)
		return
	}
	if match := taskPath.FindStringSubmatch(r.URL.Path); r.Method == http.MethodGet && match != nil {
		time.Sleep(api.readDelay)
		task, ok := api.tasks[match[1]]
		if !ok {
			refuse(http.StatusNotFound, "not_found")
			return
		}
		script := api.script[task.ID]
		if len(script) == 0 {
			script = []string{"succeeded"}
		}
		task.Status = script[0]
		if len(script) > 1 {
			api.script[task.ID] = script[1:]
		}
		switch {
		case task.Status == "succeeded" && task.Type == "CloudflareChallengeTask":
			agent := "Mozilla/5.0 (stand-in)"
			task.Cost, task.Held, task.TokenExpiresAt = "0.001200", "0.000000", "2026-09-30T10:30:00Z"
			task.Solution = &Solution{
				Token:     "stand-in-clearance",
				UserAgent: &agent,
				Cookie:    &ClearanceCookie{Name: "cf_clearance", Value: "stand-in-clearance"},
			}
		case task.Status == "succeeded":
			task.Cost, task.Held, task.Solution = "0.000800", "0.000000", &Solution{Token: "0.stand-in-token"}
		case task.Status == "failed":
			task.Held = "0.000000"
			task.ErrorCode = "ERROR_CAPTCHA_UNSOLVABLE"
			task.ErrorDescription = "The task could not be solved. Nothing was charged."
		}
		send(http.StatusOK, task)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/balance" {
		send(http.StatusOK, Balance{Available: "14.100000", Held: "0.000800", Currency: "USD"})
		return
	}
	refuse(http.StatusNotFound, "not_found")
}

func (api *standIn) requests() []seen {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]seen(nil), api.seen...)
}

func client(t *testing.T, api *standIn) *Client {
	t.Helper()
	c, err := NewClient(key, api.server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var task = NewTask{WebsiteURL: "https://shop.example.com/login", WebsiteKey: "0x4AAAAAAAB1cD2eF3gH4iJ5"}

var quick = WaitOptions{Interval: 5 * time.Millisecond}

func TestSolveCreatesAProxylessTaskPollsItAndReturnsItsToken(t *testing.T) {
	api := newStandIn(t)
	api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = []string{"queued", "running", "succeeded"}
	token, err := client(t, api).Solve(context.Background(), task, quick)
	if err != nil || token != "0.stand-in-token" {
		t.Fatalf("Solve = %q, %v", token, err)
	}
	requests := api.requests()
	create := requests[0]
	if create.method != http.MethodPost || create.path != "/v1/tasks" {
		t.Fatalf("first request %s %s", create.method, create.path)
	}
	if create.body["type"] != "TurnstileTaskProxyless" || create.body["websiteURL"] != task.WebsiteURL {
		t.Fatalf("body %v", create.body)
	}
	if _, ok := create.body["proxy"]; ok {
		t.Fatalf("an empty proxy was sent: %v", create.body)
	}
	if len(create.header.Get("Idempotency-Key")) != 32 {
		t.Fatalf("idempotency key %q", create.header.Get("Idempotency-Key"))
	}
	if len(requests) != 4 {
		t.Fatalf("%d requests, want 4", len(requests))
	}
}

func TestSolveChallengeGoesThroughTheProxyAndReturnsTheClearance(t *testing.T) {
	api := newStandIn(t)
	api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = []string{"running", "succeeded"}
	page := NewChallengeTask{WebsiteURL: "https://shop.example.com/", Proxy: "http://user:pass@proxy.example.net:8080"}
	clearance, err := client(t, api).SolveChallenge(context.Background(), page, quick)
	if err != nil {
		t.Fatal(err)
	}
	want := Clearance{CfClearance: "stand-in-clearance", UserAgent: "Mozilla/5.0 (stand-in)", TokenExpiresAt: "2026-09-30T10:30:00Z"}
	if *clearance != want {
		t.Fatalf("SolveChallenge = %+v", *clearance)
	}
	sent := api.requests()[0]
	if sent.body["type"] != "CloudflareChallengeTask" || sent.body["proxy"] != page.Proxy || sent.body["websiteURL"] != page.WebsiteURL {
		t.Fatalf("body %v", sent.body)
	}
	if _, ok := sent.body["websiteKey"]; ok {
		t.Fatalf("a site key was sent: %v", sent.body)
	}
	if len(sent.header.Get("Idempotency-Key")) != 32 {
		t.Fatalf("idempotency key %q", sent.header.Get("Idempotency-Key"))
	}
}

func TestAChallengeThatFailsIsATaskFailedError(t *testing.T) {
	api := newStandIn(t)
	api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = []string{"failed"}
	page := NewChallengeTask{WebsiteURL: "https://shop.example.com/", Proxy: "http://proxy.example.net:8080"}
	_, err := client(t, api).SolveChallenge(context.Background(), page, quick)
	var failure *TaskFailedError
	if !errors.As(err, &failure) || failure.Code != "ERROR_CAPTCHA_UNSOLVABLE" {
		t.Fatalf("err = %v", err)
	}
}

func TestAProxyMakesAProxyTaskAndTheCallbackURLIsSent(t *testing.T) {
	api := newStandIn(t)
	proxied := task
	proxied.Proxy = "http://user:pass@proxy.example.net:8080"
	proxied.CallbackURL = "https://hooks.example.com/zc"
	if _, err := client(t, api).CreateTask(context.Background(), proxied, CreateOptions{IdempotencyKey: "order-1234"}); err != nil {
		t.Fatal(err)
	}
	sent := api.requests()[0]
	if sent.body["type"] != "TurnstileTask" || sent.body["callbackUrl"] != "https://hooks.example.com/zc" {
		t.Fatalf("body %v", sent.body)
	}
	if sent.header.Get("Idempotency-Key") != "order-1234" {
		t.Fatalf("idempotency key %q", sent.header.Get("Idempotency-Key"))
	}
}

func TestATaskThatFailsIsATaskFailedErrorWithItsCode(t *testing.T) {
	api := newStandIn(t)
	api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = []string{"running", "failed"}
	_, err := client(t, api).Solve(context.Background(), task, quick)
	var failure *TaskFailedError
	if !errors.As(err, &failure) || failure.Code != "ERROR_CAPTCHA_UNSOLVABLE" || failure.Task.Cost != "0.000000" {
		t.Fatalf("err = %v", err)
	}
}

func TestAWaitThatRunsOutIsAWaitTimeoutError(t *testing.T) {
	api := newStandIn(t)
	c := client(t, api)
	created, err := c.CreateTask(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	api.script[created.ID] = []string{"running"}
	api.mu.Unlock()
	_, err = c.WaitForResult(context.Background(), created.ID, WaitOptions{Timeout: 30 * time.Millisecond, Interval: 5 * time.Millisecond})
	var timeout *WaitTimeoutError
	if !errors.As(err, &timeout) || timeout.Task == nil || timeout.Task.Status != "running" {
		t.Fatalf("err = %v", err)
	}
}

// Codex review finding 5: the deadline was checked only after a read finished.
func TestASlowReadDoesNotCarryTheWaitPastItsDeadline(t *testing.T) {
	api := newStandIn(t)
	c := client(t, api)
	created, err := c.CreateTask(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	api.readDelay = 2 * time.Second
	api.mu.Unlock()
	started := time.Now()
	_, err = c.WaitForResult(context.Background(), created.ID, WaitOptions{Timeout: 100 * time.Millisecond, Interval: 5 * time.Millisecond})
	if took := time.Since(started); took > time.Second {
		t.Fatalf("the wait took %v", took)
	}
	var timeout *WaitTimeoutError
	if !errors.As(err, &timeout) || timeout.Task != nil || timeout.TaskID != created.ID {
		t.Fatalf("err = %v", err)
	}
}

func TestARetryAfterLongerThanTheTimeLeftEndsTheWaitAtOnce(t *testing.T) {
	api := newStandIn(t)
	c := client(t, api)
	created, err := c.CreateTask(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	api.script[created.ID] = []string{"running"}
	api.refusals = []refusal{{status: http.StatusTooManyRequests, code: "rate_limited", retryAfter: "5"}}
	api.mu.Unlock()
	started := time.Now()
	_, err = c.WaitForResult(context.Background(), created.ID, WaitOptions{Timeout: 200 * time.Millisecond, Interval: 5 * time.Millisecond})
	if took := time.Since(started); took > time.Second {
		t.Fatalf("the wait took %v", took)
	}
	var timeout *WaitTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v", err)
	}
}

// Codex review finding 6: a body that could not be read was not retried, so a task the API made
// surfaced as an error, and calling again made a second, paid task.
func TestAnAnswerCutShortIsRetriedWithTheSameKeyAndMakesOneTask(t *testing.T) {
	api := newStandIn(t)
	api.cutBodies = 1
	created, err := client(t, api).CreateTask(context.Background(), task)
	if err != nil || created.Status != "queued" {
		t.Fatalf("CreateTask = %v, %v", created, err)
	}
	requests := api.requests()
	if len(requests) != 2 || requests[0].header.Get("Idempotency-Key") != requests[1].header.Get("Idempotency-Key") {
		t.Fatalf("requests %v", requests)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.tasks) != 1 {
		t.Fatalf("%d tasks, want 1", len(api.tasks))
	}
}

func TestA429IsRetriedAfterRetryAfterWithTheSameKey(t *testing.T) {
	api := newStandIn(t)
	api.refusals = []refusal{{status: http.StatusTooManyRequests, code: "rate_limited", retryAfter: "0"}}
	created, err := client(t, api).CreateTask(context.Background(), task)
	if err != nil || created.Status != "queued" {
		t.Fatalf("CreateTask = %v, %v", created, err)
	}
	requests := api.requests()
	if len(requests) != 2 || requests[0].header.Get("Idempotency-Key") != requests[1].header.Get("Idempotency-Key") {
		t.Fatalf("requests %v", requests)
	}
}

func TestARefusalIsAnAPIErrorWithTheAPIsCodeAndRequestID(t *testing.T) {
	api := newStandIn(t)
	api.refusals = []refusal{{status: http.StatusPaymentRequired, code: "insufficient_funds"}}
	_, err := client(t, api).CreateTask(context.Background(), task)
	var failure *APIError
	if !errors.As(err, &failure) || failure.Status != 402 || failure.Code != "insufficient_funds" ||
		failure.RequestID != "req-1" || failure.Message != "Refused: insufficient_funds." {
		t.Fatalf("err = %#v", err)
	}
	if len(api.requests()) != 1 {
		t.Fatalf("a refusal was retried")
	}
}

func TestTheBalanceIsReadWithTheKeyAsABearerToken(t *testing.T) {
	api := newStandIn(t)
	balance, err := client(t, api).GetBalance(context.Background())
	if err != nil || *balance != (Balance{Available: "14.100000", Held: "0.000800", Currency: "USD"}) {
		t.Fatalf("GetBalance = %v, %v", balance, err)
	}
	if api.requests()[0].header.Get("Authorization") != "Bearer "+key {
		t.Fatal("the key was not a bearer token")
	}
}

func TestAKeyOrAddressThatCannotBeRightIsRefusedAtOnce(t *testing.T) {
	if _, err := NewClient("sk_test", "https://api.example.com"); err == nil {
		t.Fatal("a key that is not one was taken")
	}
	if _, err := NewClient(key, "api.example.com"); err == nil {
		t.Fatal("an address without a scheme was taken")
	}
}

func TestAnEmptyBaseURLIsTheZeroCaptchaAPI(t *testing.T) {
	if DefaultBaseURL != "https://api.zerocaptcha.io" {
		t.Fatalf("DefaultBaseURL = %q", DefaultBaseURL)
	}
	client, err := NewClient(key, "")
	if err != nil || client.baseURL != DefaultBaseURL {
		t.Fatalf("NewClient(key, \"\") = %v, %v", client, err)
	}
}

func TestCallbackSignatures(t *testing.T) {
	secret := "zcsig_ExampleCallbackSecretShownToOwnersOnly0Z"
	body := []byte(`{"id":"0192f3a4","status":"succeeded"}`)
	now := time.Unix(1_790_000_000, 0)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("1790000000."))
	mac.Write(body)
	v1 := hex.EncodeToString(mac.Sum(nil))
	header := "t=1790000000,v1=" + v1
	if !VerifySignature(secret, header, body, 0, now) {
		t.Fatal("a genuine call did not verify")
	}
	for name, ok := range map[string]bool{
		"another body":   VerifySignature(secret, header, append(body, ' '), 0, now),
		"another secret": VerifySignature(secret+"x", header, body, 0, now),
		"another time":   VerifySignature(secret, "t=1790000001,v1="+v1, body, 0, now),
		"an old call":    VerifySignature(secret, header, body, 0, now.Add(301*time.Second)),
		"no signature":   VerifySignature(secret, "v1=abc", body, 0, now),
		"no header":      VerifySignature(secret, "", body, 0, now),
		"upper case hex": VerifySignature(secret, "t=1790000000,v1="+strings.ToUpper(v1), body, 0, now),
	} {
		if ok {
			t.Errorf("%s verified", name)
		}
	}
}
