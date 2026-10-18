package permio

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Kind classifies an Error.
type Kind string

const (
	// KindConfig: the client was configured incorrectly (e.g. a malformed API key).
	KindConfig Kind = "config"
	// KindAuth: the API key was missing, unknown or revoked (gRPC Unauthenticated).
	KindAuth Kind = "auth"
	// KindPermission: the API key is valid but may not make this call (gRPC
	// PermissionDenied), e.g. a check-only key trying to write, or a project the
	// key does not belong to.
	KindPermission Kind = "permission_denied"
	// KindInvalid: the request was rejected as malformed (gRPC InvalidArgument).
	KindInvalid Kind = "invalid_argument"
	// KindNotFound: the entity does not exist (gRPC NotFound).
	KindNotFound Kind = "not_found"
	// KindAlreadyExists: the entity already exists (gRPC AlreadyExists).
	KindAlreadyExists Kind = "already_exists"
	// KindUnavailable: the API could not be reached (gRPC Unavailable).
	KindUnavailable Kind = "unavailable"
	// KindTimeout: the call did not finish in time (gRPC DeadlineExceeded).
	KindTimeout Kind = "timeout"
	// KindOther: anything else.
	KindOther Kind = "error"
)

// MissingPermission lists permissions missing on one resource.
type MissingPermission struct {
	Resource    string   `json:"resource"`
	Permissions []string `json:"permissions"`
}

// Error is returned by every Client call that fails.
type Error struct {
	Kind    Kind
	Code    codes.Code
	Message string
	// Missing is parsed from PermissionDenied messages: what the API key lacks.
	// The URIs are the server's fully qualified internal URIs.
	Missing []MissingPermission
	cause   error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Kind)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.cause }

// The permissions service formats PermissionDenied as Go's %+v of its missing list:
//
//	missing permissions: [{ResourceURI:/organisation/o/project/p/doc MissingPermissions:[permission.check]} ...]
var missingEntry = regexp.MustCompile(`\{ResourceURI:(\S*) MissingPermissions:\[([^\]]*)\]\}`)

func parseMissing(msg string) []MissingPermission {
	var out []MissingPermission
	for _, m := range missingEntry.FindAllStringSubmatch(msg, -1) {
		out = append(out, MissingPermission{Resource: m[1], Permissions: strings.Fields(m[2])})
	}
	return out
}

// toError converts a gRPC (or context) error into an *Error.
func toError(err error) error {
	if err == nil {
		return nil
	}
	var pe *Error
	if errors.As(err, &pe) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: KindTimeout, Code: codes.DeadlineExceeded, Message: "request timed out", cause: err}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Kind: KindOther, Code: codes.Canceled, Message: "request cancelled", cause: err}
	}
	st, ok := status.FromError(err)
	if !ok {
		return &Error{Kind: KindOther, Code: codes.Unknown, Message: err.Error(), cause: err}
	}
	e := &Error{Code: st.Code(), Message: st.Message(), cause: err}
	switch st.Code() {
	case codes.Unauthenticated:
		e.Kind = KindAuth
		if e.Message == "" {
			e.Message = "the API key was rejected"
		}
	case codes.PermissionDenied:
		e.Kind = KindPermission
		e.Missing = parseMissing(st.Message())
		if len(e.Missing) > 0 {
			e.Message = "permission denied for the API key"
		}
	case codes.InvalidArgument:
		e.Kind = KindInvalid
	case codes.NotFound:
		e.Kind = KindNotFound
	case codes.AlreadyExists:
		e.Kind = KindAlreadyExists
	case codes.Unavailable:
		e.Kind = KindUnavailable
	case codes.DeadlineExceeded:
		e.Kind = KindTimeout
	default:
		e.Kind = KindOther
	}
	if e.Message == "" {
		e.Message = st.Code().String()
	}
	return e
}

// KindOf returns the Kind of err, or "" if it is not an *Error.
func KindOf(err error) Kind {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Kind
	}
	return ""
}

// IsNotFound reports whether err is a NotFound error.
func IsNotFound(err error) bool { return KindOf(err) == KindNotFound }

func configError(format string, args ...any) error {
	return &Error{Kind: KindConfig, Message: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return &Error{Kind: KindInvalid, Code: codes.InvalidArgument, Message: fmt.Sprintf(format, args...)}
}

func alreadyExists(format string, args ...any) error {
	return &Error{Kind: KindAlreadyExists, Code: codes.AlreadyExists, Message: fmt.Sprintf(format, args...)}
}

// isInternal reports whether err is a gRPC Internal error, which the API uses
// for failures it does not classify (e.g. unique-index clashes).
func isInternal(err error) bool {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Code == codes.Internal
	}
	return status.Code(err) == codes.Internal
}
