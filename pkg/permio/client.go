// Package permio is the CLI's client layer over the public Go SDK,
// github.com/perms-io/permio-go. The SDK provides auth, timeouts, retries
// for idempotent reads and typed errors; this package adds what the CLI needs
// on top: whole sorted listings, role lookup by name, and every grant in a
// project.
package permio

import (
	"time"

	sdk "github.com/perms-io/permio-go"
	permissionsv1 "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
)

// Options configures a Client.
type Options struct {
	// APIKey is a "perms_" key from the dashboard, or a legacy JWT key.
	APIKey string
	// Address is the gateway's host:port, e.g. "api.perms.io:443".
	Address string
	// Insecure dials without TLS. Only for local servers.
	Insecure bool
	// Project is the project_name sent with every request.
	Project string
	// Timeout per attempt. Default 15s.
	Timeout time.Duration
	// Retries for idempotent reads on Unavailable or DeadlineExceeded. Default 2;
	// set a negative value to disable. Writes are never retried.
	Retries int
	// UserAgent is prepended to grpc-go's user agent.
	UserAgent string
	// DialOptions are appended to the default dial options (used by tests).
	DialOptions []grpc.DialOption
}

// Client talks to the PermissionsService.
type Client struct {
	// SDK is the public SDK client, in Project.
	SDK *sdk.Client
	// Raw is the generated client, with auth, timeouts, retries and error
	// mapping applied.
	Raw     permissionsv1.PermissionsServiceClient
	Project string
}

// New validates the API key and creates a client. It does not connect until
// the first call. A malformed key is a KindAuth error.
func New(opts Options) (*Client, error) {
	if _, err := sdk.ValidateAPIKey(opts.APIKey); err != nil {
		// The CLI reports a malformed key like a rejected one (exit code 3).
		return nil, &Error{Kind: KindAuth, Message: err.(*Error).Message}
	}
	if opts.Address == "" {
		return nil, &Error{Kind: KindConfig, Message: "no API address configured"}
	}
	if opts.Project == "" {
		return nil, &Error{Kind: KindConfig, Message: "no project configured"}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	c, err := sdk.New(sdk.Options{
		APIKey:      opts.APIKey,
		Endpoint:    opts.Address,
		Insecure:    opts.Insecure,
		Project:     opts.Project,
		Timeout:     opts.Timeout,
		Retry:       sdk.RetryOptions{MaxRetries: opts.Retries},
		UserAgent:   opts.UserAgent,
		DialOptions: opts.DialOptions,
	})
	if err != nil {
		return nil, err
	}
	return &Client{SDK: c, Raw: c.Permissions(), Project: opts.Project}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.SDK.Close() }

// InProject returns a client that sends project instead of c.Project. It
// shares c's connection; close only the original.
func (c *Client) InProject(project string) *Client {
	s := c.SDK.WithProject(project)
	return &Client{SDK: s, Raw: s.Permissions(), Project: project}
}
