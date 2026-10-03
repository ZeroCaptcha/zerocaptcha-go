// Package zerocaptcha is ZeroCaptcha's official Go client: create a Cloudflare Turnstile task,
// wait for its result, read the balance, and check a task callback's signature. It uses the
// standard library only.
//
//	client, err := zerocaptcha.NewClient(os.Getenv("ZEROCAPTCHA_KEY"), os.Getenv("ZEROCAPTCHA_API"))
//	token, err := client.Solve(ctx, zerocaptcha.NewTask{
//		WebsiteURL: "https://shop.example.com/login",
//		WebsiteKey: "0x4AAAAAAAB1cD2eF3gH4iJ5",
//	})
package zerocaptcha

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version is this client's version.
const Version = "0.1.0"

// SignatureHeader is the header each callback carries: t=<unix seconds>,v1=<hex HMAC-SHA256>.
const SignatureHeader = "ZeroCaptcha-Signature"

// NewTask is a Turnstile task to create.
type NewTask struct {
	// Type is TurnstileTaskProxyless, or TurnstileTask to solve through Proxy. Left empty, it is
	// TurnstileTask when Proxy is set and TurnstileTaskProxyless otherwise.
	Type string `json:"type"`
	// WebsiteURL is the page the widget is on.
	WebsiteURL string `json:"websiteURL"`
	// WebsiteKey is the widget's site key.
	WebsiteKey string `json:"websiteKey"`
	// Action is the widget's action, if it sets one.
	Action string `json:"action,omitempty"`
	// CData is the widget's cData, if it sets one.
	CData string `json:"cdata,omitempty"`
	// Proxy is your proxy as a URL with its port, such as http://user:pass@proxy.example.net:8080.
	Proxy string `json:"proxy,omitempty"`
	// CallbackURL is where to POST the task once it ends, signed with your callback secret.
	CallbackURL string `json:"callbackUrl,omitempty"`
}

// Solution holds a solved task's token. A challenge page's also names the user agent its
// cf_clearance cookie is bound to, and the cookie.
type Solution struct {
	Token     string           `json:"token"`
	UserAgent *string          `json:"userAgent"`
	Cookie    *ClearanceCookie `json:"cookie"`
}

// ClearanceCookie is a challenge page's cf_clearance cookie.
type ClearanceCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// ExpiresAt is when the site stops accepting it, if that is known; nil while it is not.
	ExpiresAt *string `json:"expiresAt"`
}

// NewChallengeTask is a Cloudflare challenge page's task (CloudflareChallengeTask), always through
// your proxy: its clearance works only from the proxy's address, with the user agent that earned it.
type NewChallengeTask struct {
	// WebsiteURL is the page behind the challenge.
	WebsiteURL string `json:"websiteURL"`
	// Proxy is your proxy as a URL with its port, such as http://user:pass@proxy.example.net:8080.
	Proxy string `json:"proxy"`
	// CallbackURL is where to POST the task once it ends, signed with your callback secret.
	CallbackURL string `json:"callbackUrl,omitempty"`
}

// Clearance is a challenge page's clearance: send CfClearance as the cf_clearance cookie, with
// exactly UserAgent, through the proxy the task used.
type Clearance struct {
	CfClearance string
	UserAgent   string
	// TokenExpiresAt is until when the API serves the clearance; the site decides how long it works.
	TokenExpiresAt string
}

// Task is a task as the API shows it. Amounts are US dollars, as decimal strings.
type Task struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"`
	Status           string    `json:"status"`
	Kind             string    `json:"kind"`
	WebsiteURL       string    `json:"websiteURL"`
	WebsiteKey       string    `json:"websiteKey"`
	Price            string    `json:"price"`
	Held             string    `json:"held"`
	Cost             string    `json:"cost"`
	ErrorCode        string    `json:"errorCode"`
	ErrorDescription string    `json:"errorDescription"`
	Solution         *Solution `json:"solution"`
	TokenExpiresAt   string    `json:"tokenExpiresAt"`
	CreatedAt        string    `json:"createdAt"`
}

// Balance is the account's balance, in US dollars as decimal strings.
type Balance struct {
	// Available is what new tasks can be held against.
	Available string `json:"available"`
	// Held is held for tasks that are queued or running.
	Held     string `json:"held"`
	Currency string `json:"currency"`
}

// APIError is a request the API refused, or could not serve.
type APIError struct {
	// Status is the HTTP status; 0 when the request never got an answer.
	Status int
	// Code is the API's stable error code, such as insufficient_funds or rate_limited.
	Code string
	// Message says what went wrong.
	Message string
	// RequestID is the ID to quote when you ask support about this request.
	RequestID string
	// RetryAfter is how long the API asked you to wait before trying again.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zerocaptcha: %s (%s)", e.Message, e.Code)
}

// TaskFailedError is a task that ended without a token: it failed or expired, and nothing was
// charged.
type TaskFailedError struct {
	Task *Task
	// Code is such as ERROR_CAPTCHA_UNSOLVABLE, from the task's errorCode.
	Code string
}

func (e *TaskFailedError) Error() string {
	if e.Task.ErrorDescription != "" {
		return "zerocaptcha: " + e.Task.ErrorDescription
	}
	return "zerocaptcha: the task " + e.Task.Status
}

// WaitTimeoutError is a task that had not ended when the wait ran out; it may still end.
type WaitTimeoutError struct {
	// Task is the task as it was last read; nil when no read finished before the wait ran out.
	Task *Task
	// TaskID is the task waited for.
	TaskID string
}

func (e *WaitTimeoutError) Error() string {
	if e.Task == nil {
		return "zerocaptcha: the wait ran out before the task could be read"
	}
	return "zerocaptcha: the task was still " + e.Task.Status + " when the wait ran out"
}

// DefaultBaseURL is the API's address NewClient uses when its baseURL is empty.
const DefaultBaseURL = "https://api.zerocaptcha.io"

// Client is the ZeroCaptcha API, as one account's key sees it. It is safe for concurrent use.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// Option changes how a Client is made.
type Option func(*Client)

// WithHTTPClient uses client for every request, such as one with its own timeout or transport.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) { c.http = client }
}

// NewClient makes a client for apiKey (zc_live_…) and the API at baseURL, or at DefaultBaseURL,
// https://api.zerocaptcha.io, when baseURL is empty. Each request may take 30 seconds unless
// WithHTTPClient says otherwise.
func NewClient(apiKey, baseURL string, options ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "zc_live_") {
		return nil, errors.New("zerocaptcha: the API key must be a ZeroCaptcha key, zc_live_…")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("zerocaptcha: the base URL must be the API's http or https address")
	}
	client := &Client{
		apiKey:  apiKey,
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	for _, option := range options {
		option(client)
	}
	return client, nil
}

// CreateOptions changes how a task is created.
type CreateOptions struct {
	// IdempotencyKey is your ID for this task, 1 to 255 visible ASCII characters: the same one
	// again returns the first task instead of making a second. One is made for each call when it
	// is empty, so the client's own retries never make two tasks.
	IdempotencyKey string
}

// CreateTask creates a task; it is charged only if it succeeds.
func (c *Client) CreateTask(ctx context.Context, task NewTask, options ...CreateOptions) (*Task, error) {
	if task.Type == "" {
		task.Type = "TurnstileTaskProxyless"
		if task.Proxy != "" {
			task.Type = "TurnstileTask"
		}
	}
	return c.create(ctx, task, options)
}

// CreateChallengeTask creates a Cloudflare challenge page's task, through your proxy; it is
// charged only if it succeeds.
func (c *Client) CreateChallengeTask(ctx context.Context, task NewChallengeTask, options ...CreateOptions) (*Task, error) {
	body := struct {
		Type string `json:"type"`
		NewChallengeTask
	}{"CloudflareChallengeTask", task}
	return c.create(ctx, body, options)
}

// create posts a new task with the options' Idempotency-Key, or one of its own.
func (c *Client) create(ctx context.Context, body any, options []CreateOptions) (*Task, error) {
	key := ""
	for _, option := range options {
		if option.IdempotencyKey != "" {
			key = option.IdempotencyKey
		}
	}
	if key == "" {
		made, err := randomKey()
		if err != nil {
			return nil, err
		}
		key = made
	}
	var created Task
	if err := c.do(ctx, http.MethodPost, "/v1/tasks", body, key, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// GetTask reads a task; its token is in Solution while it is available.
func (c *Client) GetTask(ctx context.Context, id string) (*Task, error) {
	var task Task
	if err := c.do(ctx, http.MethodGet, "/v1/tasks/"+url.PathEscape(id), nil, "", &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// WaitOptions changes how long and how often WaitForResult asks.
type WaitOptions struct {
	// Timeout is how long to wait for a final status; 3 minutes when zero.
	Timeout time.Duration
	// Interval is how often to ask; 2 seconds when zero.
	Interval time.Duration
}

// WaitForResult waits for a task to end, and returns it once it succeeded. A task that failed or
// expired is a *TaskFailedError; a wait that ran out first is a *WaitTimeoutError. The wait never
// runs past its Timeout: each read gets only the time left, and a retry that would wait longer
// than that, such as after a long Retry-After, is not made.
func (c *Client) WaitForResult(ctx context.Context, id string, options ...WaitOptions) (*Task, error) {
	timeout, interval := 3*time.Minute, 2*time.Second
	for _, option := range options {
		if option.Timeout > 0 {
			timeout = option.Timeout
		}
		if option.Interval > 0 {
			interval = option.Interval
		}
	}
	deadline := time.Now().Add(timeout)
	waiting, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var last *Task
	for {
		task, err := c.GetTask(waiting, id)
		if err != nil {
			// The wait's own deadline, not the caller's context.
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return nil, &WaitTimeoutError{Task: last, TaskID: id}
			}
			return nil, err
		}
		last = task
		switch task.Status {
		case "succeeded":
			return task, nil
		case "failed", "expired":
			return nil, failed(task)
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, &WaitTimeoutError{Task: task, TaskID: id}
		}
		if err := sleep(ctx, min(interval, left)); err != nil {
			return nil, err
		}
	}
}

// Solve creates a task and waits for it, and returns its token.
func (c *Client) Solve(ctx context.Context, task NewTask, options ...WaitOptions) (string, error) {
	created, err := c.CreateTask(ctx, task)
	if err != nil {
		return "", err
	}
	done, err := c.WaitForResult(ctx, created.ID, options...)
	if err != nil {
		return "", err
	}
	if done.Solution == nil {
		return "", failed(done)
	}
	return done.Solution.Token, nil
}

// SolveChallenge creates a challenge page's task and waits for it, and returns its clearance.
func (c *Client) SolveChallenge(ctx context.Context, task NewChallengeTask, options ...WaitOptions) (*Clearance, error) {
	created, err := c.CreateChallengeTask(ctx, task)
	if err != nil {
		return nil, err
	}
	done, err := c.WaitForResult(ctx, created.ID, options...)
	if err != nil {
		return nil, err
	}
	if done.Solution == nil || done.Solution.Cookie == nil || done.Solution.UserAgent == nil {
		return nil, failed(done)
	}
	return &Clearance{
		CfClearance:    done.Solution.Cookie.Value,
		UserAgent:      *done.Solution.UserAgent,
		TokenExpiresAt: done.TokenExpiresAt,
	}, nil
}

// GetBalance reads the account's balance.
func (c *Client) GetBalance(ctx context.Context) (*Balance, error) {
	var balance Balance
	if err := c.do(ctx, http.MethodGet, "/v1/balance", nil, "", &balance); err != nil {
		return nil, err
	}
	return &balance, nil
}

func failed(task *Task) *TaskFailedError {
	code := task.ErrorCode
	if code == "" {
		code = "failed"
		if task.Status == "expired" {
			code = "ERROR_TASK_TIMEOUT"
		}
	}
	return &TaskFailedError{Task: task, Code: code}
}

// attempts is how many times one call is tried in all.
const attempts = 3

// retryable says whether a refusal may pass if the same request is sent again after a wait: too
// many requests, a server busy or away, or the first request with this key still being served.
func retryable(failure *APIError) bool {
	switch failure.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	case http.StatusConflict:
		return failure.Code == "idempotency_key_in_use"
	}
	return false
}

// do sends one call, trying it up to attempts times with the same Idempotency-Key: after no
// answer, an answer cut short (its body could not be read, or a success's did not parse), or a
// retryable refusal. No attempt and no wait runs past ctx's deadline: a retry that would wait
// longer than the time left is not made, and ctx's deadline error says so.
func (c *Client) do(ctx context.Context, method, path string, body any, key string, into any) error {
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = encoded
	}
	var failure *APIError
	for attempt := 1; attempt <= attempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "zerocaptcha-go/"+Version)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		wait := time.Duration(500*math.Pow(2, float64(attempt))) * time.Millisecond
		response, err := c.http.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failure = &APIError{Code: "network", Message: "the request got no answer: " + err.Error()}
		} else {
			// The body is part of the answer: one cut short is retried as no answer is, with the
			// same Idempotency-Key, so a task the API made is returned rather than made again.
			text, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			switch {
			case readErr != nil:
				if ctx.Err() != nil {
					return ctx.Err()
				}
				failure = &APIError{Code: "network", Message: "the answer was cut short: " + readErr.Error()}
			case response.StatusCode >= 200 && response.StatusCode < 300:
				parseErr := json.Unmarshal(text, into)
				if parseErr == nil {
					return nil
				}
				failure = &APIError{Status: response.StatusCode, Code: "network", Message: "the answer was cut short: " + parseErr.Error()}
			default:
				failure = problem(response, text)
				if !retryable(failure) {
					return failure
				}
				if failure.RetryAfter > 0 || response.Header.Get("Retry-After") != "" {
					wait = failure.RetryAfter
				}
			}
		}
		if attempt == attempts {
			break
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= wait {
			return context.DeadlineExceeded
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	return failure
}

func problem(response *http.Response, text []byte) *APIError {
	var fields struct {
		Code      string `json:"code"`
		Title     string `json:"title"`
		Detail    string `json:"detail"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(text, &fields)
	failure := &APIError{
		Status:    response.StatusCode,
		Code:      fields.Code,
		Message:   fields.Detail,
		RequestID: fields.RequestID,
	}
	if failure.Code == "" {
		failure.Code = "http_" + strconv.Itoa(response.StatusCode)
	}
	if failure.Message == "" {
		failure.Message = fields.Title
	}
	if failure.Message == "" {
		failure.Message = "HTTP " + strconv.Itoa(response.StatusCode)
	}
	if failure.RequestID == "" {
		failure.RequestID = response.Header.Get("X-Request-Id")
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After"))); err == nil && seconds >= 0 {
		failure.RetryAfter = time.Duration(seconds) * time.Second
	}
	return failure
}

func sleep(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

var signature = regexp.MustCompile(`^t=(\d+),v1=([0-9a-f]{64})$`)

// VerifySignature says whether a callback is genuine: header is its ZeroCaptcha-Signature, body
// the raw body as it arrived, before any parsing, and secret your callback secret, zcsig_…. The
// signature is the HMAC-SHA256 of <t>.<body>; a call more than tolerance away from now is refused
// too (5 minutes when tolerance is zero).
func VerifySignature(secret, header string, body []byte, tolerance time.Duration, now time.Time) bool {
	match := signature.FindStringSubmatch(strings.TrimSpace(header))
	if match == nil {
		return false
	}
	sent, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return false
	}
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
	}
	if now.IsZero() {
		now = time.Now()
	}
	age := now.Sub(time.Unix(sent, 0))
	if age > tolerance || age < -tolerance {
		return false
	}
	given, err := hex.DecodeString(match[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(match[1] + "."))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), given)
}
