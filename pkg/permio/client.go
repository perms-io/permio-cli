// Package permio is a small Go client for the perms.io PermissionsService,
// built on the generated github.com/PrivateJAR/permio-go stubs. It adds API key
// auth, timeouts, retries for idempotent reads, typed errors and helpers that
// follow pagination.
//
// It is used by the permio CLI and is not yet a stable public API.
package permio

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"strings"
	"time"

	permissionsv1 "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/PrivateJAR/permio-cli/pkg/apikey"
)

// Options configures a Client.
type Options struct {
	// APIKey is a "perms_" key from the dashboard, or a legacy JWT key.
	APIKey string
	// Address is the gateway's host:port, e.g. "temp-api.perms.io:443".
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
	// Raw is the generated client, with auth, timeouts, retries and error
	// mapping applied.
	Raw     permissionsv1.PermissionsServiceClient
	Project string
	conn    *grpc.ClientConn
}

// New validates the API key and creates a client. It does not connect until
// the first call.
func New(opts Options) (*Client, error) {
	if _, err := apikey.Validate(opts.APIKey); err != nil {
		return nil, &Error{Kind: KindAuth, Message: err.Error()}
	}
	if opts.Address == "" {
		return nil, configError("no API address configured")
	}
	if opts.Project == "" {
		return nil, configError("no project configured")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	retries := opts.Retries
	if retries == 0 {
		retries = 2
	} else if retries < 0 {
		retries = 0
	}
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if opts.Insecure {
		creds = insecure.NewCredentials()
	}
	dial := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithChainUnaryInterceptor(interceptor("Bearer "+opts.APIKey, opts.Timeout, retries)),
	}
	if opts.UserAgent != "" {
		dial = append(dial, grpc.WithUserAgent(opts.UserAgent))
	}
	dial = append(dial, opts.DialOptions...)
	conn, err := grpc.NewClient(opts.Address, dial...)
	if err != nil {
		return nil, configError("invalid API address %q: %v", opts.Address, err)
	}
	return &Client{Raw: permissionsv1.NewPermissionsServiceClient(conn), Project: opts.Project, conn: conn}, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// InProject returns a client that sends project instead of c.Project. It
// shares c's connection; close only the original.
func (c *Client) InProject(project string) *Client {
	return &Client{Raw: c.Raw, Project: project}
}

const servicePrefix = "/permio.permissions.v1.PermissionsService/"

// Read-only RPCs that are safe to repeat. Everything else is sent once.
var idempotent = map[string]bool{
	"Check": true, "BatchCheck": true, "GetPermission": true, "ListPermissions": true,
	"GetRole": true, "ListRoles": true, "GetUserPermissionsAndRolesOnResource": true,
	"ListPrincipals": true, "GetAllAssignmentsForPrincipal": true, "ListAccess": true,
	"ListPrincipalsWithAccess": true, "GetGroup": true, "ListGroups": true,
	"ListGroupMembers": true, "ListGroupsForPrincipal": true,
	"GetTotalRolesAndPermissionsForOrganisation": true,
}

// IsIdempotent reports whether the full gRPC method name is retried on failure.
func IsIdempotent(fullMethod string) bool {
	return idempotent[strings.TrimPrefix(fullMethod, servicePrefix)]
}

func interceptor(authorization string, timeout time.Duration, retries int) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", authorization)
		max := 0
		if IsIdempotent(method) {
			max = retries
		}
		delay := 100 * time.Millisecond
		for attempt := 0; ; attempt++ {
			actx, cancel := context.WithTimeout(ctx, timeout)
			err := invoker(actx, method, req, reply, cc, opts...)
			cancel()
			if err == nil {
				return nil
			}
			perr := toError(err).(*Error)
			if ctx.Err() != nil || attempt >= max || (perr.Code != codes.Unavailable && perr.Code != codes.DeadlineExceeded) {
				return perr
			}
			sleep := delay/2 + time.Duration(rand.Int64N(int64(delay/2)+1))
			select {
			case <-time.After(sleep):
			case <-ctx.Done():
				return toError(ctx.Err())
			}
			if delay < 2*time.Second {
				delay *= 2
			}
		}
	}
}
