package permio

import (
	"fmt"

	sdk "github.com/PrivateJAR/permio-go"
	"google.golang.org/grpc/codes"
)

// The types, errors and helpers below are the public SDK's
// (github.com/PrivateJAR/permio-go). They are re-exported so the CLI and
// configsync keep using this package's names.

type (
	Error             = sdk.Error
	Kind              = sdk.Kind
	MissingPermission = sdk.MissingPermission
	Permission        = sdk.Permission
	Role              = sdk.Role
	RoleRef           = sdk.RoleRef
	Group             = sdk.Group
	Grant             = sdk.Grant
	CheckResult       = sdk.CheckResult
	BatchResult       = sdk.BatchResult
	MembershipChange  = sdk.MembershipChange
	AccessScope       = sdk.AccessScope
	AccessScopes      = sdk.AccessScopes
	AccessVia         = sdk.AccessVia
	AccessEntry       = sdk.AccessEntry
)

const (
	KindConfig        = sdk.KindConfig
	KindAuth          = sdk.KindAuth
	KindPermission    = sdk.KindPermission
	KindInvalid       = sdk.KindValidation
	KindNotFound      = sdk.KindNotFound
	KindAlreadyExists = sdk.KindAlreadyExists
	KindUnavailable   = sdk.KindUnavailable
	KindTimeout       = sdk.KindTimeout
	KindOther         = sdk.KindOther

	ScopeSubtree = sdk.ScopeSubtree
	ScopePattern = sdk.ScopePattern
	ScopeExact   = sdk.ScopeExact
	ScopeUnknown = sdk.ScopeUnknown

	GroupPrefix          = sdk.GroupPrefix
	WildcardSegment      = sdk.WildcardSegment
	MaxResourceURILength = sdk.MaxResourceURILength
	// PageSize is the page size used when following pagination (the API maximum).
	PageSize = sdk.MaxPageSize
	// MaxBatch is the most resources or permissions one Check or BatchCheck accepts.
	MaxBatch = sdk.MaxBatch
)

var (
	KindOf              = sdk.KindOf
	IsNotFound          = sdk.IsNotFound
	IsIdempotent        = sdk.IsIdempotent
	GroupPrincipal      = sdk.GroupPrincipal
	ValidateResourceURI = sdk.ValidateResourceURI
)

func invalid(format string, args ...any) error {
	return &Error{Kind: KindInvalid, Code: codes.InvalidArgument, Message: fmt.Sprintf(format, args...)}
}
