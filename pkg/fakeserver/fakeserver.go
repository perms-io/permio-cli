// Package fakeserver is an in-memory PermissionsService for tests of code that
// uses the permio client. It serves over bufconn and implements the RPCs the
// CLI uses, with simple semantics that mirror the real service: API key auth scoped to one project, check-only vs
// full-access keys, request validation, hierarchical resource URIs where grants
// inherit down and a stored "_" segment matches any one segment, roles,
// groups, and cursor pagination.
package fakeserver

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const orgID = "org_test"

type keyInfo struct {
	project string
	full    bool
}

type grantKey struct{ principal, uri string }

type grant struct {
	perms map[string]bool
	roles map[string]bool
}

type group struct {
	pb      *pb.Group
	members map[string]time.Time
}

type project struct {
	perms  map[string]*pb.Permission
	roles  map[string]*roleRec // by ID
	grants map[grantKey]*grant
	groups map[string]*group
}

type roleRec struct {
	id, name, description string
	perms                 []string
}

// Server is the fake. Use New, then AddKey, then Dial.
type Server struct {
	pb.UnimplementedPermissionsServiceServer

	mu       sync.Mutex
	keys     map[string]keyInfo
	projects map[string]*project
	nextID   int
	calls    []string
	// DefaultPageSize is used when a request has no limit (the real default is 10).
	DefaultPageSize int
	// MaxPageSize, when set, caps every page so tests exercise pagination.
	MaxPageSize int
	// FailNext, when set, makes the next call of that method (e.g. "Check")
	// fail with this status code once. Used to test retries.
	failNext map[string]codes.Code
}

// New returns an empty fake.
func New() *Server {
	return &Server{keys: map[string]keyInfo{}, projects: map[string]*project{}, DefaultPageSize: 10, failNext: map[string]codes.Code{}}
}

// AddKey registers an API key for project. full=false is a check-only key.
func (s *Server) AddKey(key, projectName string, full bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key] = keyInfo{project: projectName, full: full}
	s.proj(projectName)
}

// FailOnce makes the next call to method fail with code.
func (s *Server) FailOnce(method string, code codes.Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext[method] = code
}

// Calls returns the mutating calls made so far, e.g. "CreateRole editor".
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.calls...)
}

// ResetCalls clears the call log.
func (s *Server) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// Dial starts the server on a bufconn listener and returns dial options that
// connect to it. The server stops when the test ends.
func (s *Server) Dial(t testing.TB) []grpc.DialOption {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(s.intercept))
	pb.RegisterPermissionsServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
}

func (s *Server) proj(name string) *project {
	p := s.projects[name]
	if p == nil {
		p = &project{perms: map[string]*pb.Permission{}, roles: map[string]*roleRec{}, grants: map[grantKey]*grant{}, groups: map[string]*group{}}
		s.projects[name] = p
	}
	return p
}

var writes = map[string]bool{
	"CreatePermission": true, "UpdatePermission": true, "DeletePermission": true,
	"CreateRole": true, "UpdateRole": true, "DeleteRole": true,
	"GrantUserPermissionsAndRolesOnResource": true, "RevokeUserPermissionsAndRolesOnResource": true,
	"CreateGroup": true, "UpdateGroup": true, "DeleteGroup": true, "AddGroupMembers": true, "RemoveGroupMembers": true,
}

type projectNamed interface{ GetProjectName() string }
type validator interface{ ValidateAll() error }

func (s *Server) intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	method := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
	s.mu.Lock()
	code, fail := s.failNext[method]
	delete(s.failNext, method)
	s.mu.Unlock()
	if fail {
		return nil, status.Error(code, "injected failure")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) == 0 || !strings.HasPrefix(auth[0], "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "missing credentials")
	}
	s.mu.Lock()
	key, ok := s.keys[strings.TrimPrefix(auth[0], "Bearer ")]
	s.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid API key")
	}
	if v, ok := req.(validator); ok {
		if err := v.ValidateAll(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
		}
	}
	if p, ok := req.(projectNamed); ok && p.GetProjectName() != key.project {
		return nil, status.Errorf(codes.PermissionDenied, "missing permissions: [{ResourceURI:/organisation/%s/project/%s MissingPermissions:[permission.check]}]", orgID, p.GetProjectName())
	}
	if writes[method] && !key.full {
		return nil, status.Errorf(codes.PermissionDenied, "missing permissions: [{ResourceURI:/organisation/%s/project/%s MissingPermissions:[%s]}]", orgID, key.project, strings.ToLower(method))
	}
	return handler(ctx, req)
}

func (s *Server) log(format string, args ...any) {
	s.calls = append(s.calls, fmt.Sprintf(format, args...))
}

// --- pagination ---

func page[T any](items []T, p *paginationv1.PaginationRequest, def, maxPage int) ([]T, *paginationv1.PaginationResponse, error) {
	limit := def
	if p.GetLimit() > 0 {
		limit = int(p.GetLimit())
	}
	if maxPage > 0 && limit > maxPage {
		limit = maxPage
	}
	start := 0
	if c := p.GetCursor(); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 || n > len(items) {
			return nil, nil, status.Error(codes.InvalidArgument, "invalid cursor")
		}
		start = n
	}
	end := min(start+limit, len(items))
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[start:end], &paginationv1.PaginationResponse{NextCursor: next}, nil
}

// --- URI matching ---

func segs(uri string) []string {
	if uri == "" || uri == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(uri, "/"), "/")
}

// covers reports whether a grant stored on g applies to resource r: g is r or
// an ancestor of r, and each "_" segment of g matches any one segment.
func covers(g, r string) bool {
	gs, rs := segs(g), segs(r)
	if len(gs) > len(rs) {
		return false
	}
	for i := range gs {
		if gs[i] != "_" && gs[i] != rs[i] {
			return false
		}
	}
	return true
}

func (p *project) groupsOf(principal string) []string {
	var out []string
	for name, g := range p.groups {
		if _, ok := g.members[principal]; ok {
			out = append(out, "group:"+name)
		}
	}
	sort.Strings(out)
	return out
}

// effective returns the permissions conferred by one grant.
func (p *project) effective(g *grant) map[string]bool {
	out := map[string]bool{}
	for perm := range g.perms {
		if p.perms[perm] != nil {
			out[perm] = true
		}
	}
	for id := range g.roles {
		if r := p.roles[id]; r != nil {
			for _, perm := range r.perms {
				if p.perms[perm] != nil {
					out[perm] = true
				}
			}
		}
	}
	return out
}

// held returns the permissions principal holds on resource, through its own
// grants and its groups' grants.
func (p *project) held(principal, resource string) map[string]bool {
	principals := append([]string{principal}, p.groupsOf(principal)...)
	out := map[string]bool{}
	for k, g := range p.grants {
		if !contains(principals, k.principal) || !covers(k.uri, resource) {
			continue
		}
		for perm := range p.effective(g) {
			out[perm] = true
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- permissions ---

func (s *Server) CreatePermission(_ context.Context, req *pb.CreatePermissionRequest) (*pb.Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	s.log("CreatePermission %s", req.Name)
	if existing := p.perms[req.Name]; existing != nil {
		if existing.Description != req.Description {
			// The real service has a unique (name, organisation) index, so this fails.
			return nil, status.Error(codes.Internal, "failed to create permission")
		}
		return existing, nil
	}
	s.nextID++
	perm := &pb.Permission{Id: fmt.Sprintf("perm-%d", s.nextID), OrganisationId: orgID, Name: req.Name, Description: req.Description, ProjectName: req.ProjectName}
	p.perms[req.Name] = perm
	return perm, nil
}

func (s *Server) GetPermission(_ context.Context, req *pb.GetPermissionRequest) (*pb.Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	perm := s.proj(req.ProjectName).perms[req.Name]
	if perm == nil {
		return nil, status.Error(codes.NotFound, "permission not found")
	}
	return perm, nil
}

func (s *Server) UpdatePermission(_ context.Context, req *pb.UpdatePermissionRequest) (*pb.Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	perm := p.perms[req.Name]
	if perm == nil {
		return nil, status.Error(codes.NotFound, "permission not found")
	}
	s.log("UpdatePermission %s", req.Name)
	perm.Description = req.Description
	if req.NewName != nil && *req.NewName != req.Name {
		delete(p.perms, req.Name)
		perm.Name = *req.NewName
		p.perms[perm.Name] = perm
	}
	return perm, nil
}

func (s *Server) DeletePermission(_ context.Context, req *pb.DeletePermissionRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	s.log("DeletePermission %s", req.Name)
	if p.perms[req.Name] == nil {
		// Like the real service, which fails when no row was deleted.
		return nil, status.Error(codes.Internal, "failed to delete permission")
	}
	delete(p.perms, req.Name)
	return &emptypb.Empty{}, nil
}

func (s *Server) ListPermissions(_ context.Context, req *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*pb.Permission
	for _, perm := range s.proj(req.ProjectName).perms {
		if req.GetSearch() == "" || strings.Contains(strings.ToLower(perm.Name), strings.ToLower(req.GetSearch())) {
			all = append(all, perm)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListPermissionsResponse{Permissions: items, Pagination: pg}, nil
}

// --- roles ---

func (s *Server) rolePB(p *project, r *roleRec) *pb.Role {
	out := &pb.Role{Id: r.id, OrganisationId: orgID, Name: r.name, Description: r.description}
	for _, name := range r.perms {
		if perm := p.perms[name]; perm != nil {
			out.Permissions = append(out.Permissions, perm)
		}
	}
	return out
}

func (p *project) missingPerms(names []string) []string {
	var out []string
	for _, n := range names {
		if p.perms[n] == nil {
			out = append(out, n)
		}
	}
	return out
}

func (s *Server) CreateRole(_ context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	s.log("CreateRole %s", req.Name)
	if m := p.missingPerms(req.Permissions); len(m) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "specified permissions not found: %v", m)
	}
	for _, r := range p.roles {
		if r.name == req.Name {
			// The real service returns the existing role when the request matches it
			// exactly, and fails on its unique (name, organisation) index otherwise.
			if r.description == req.Description && sameSet(r.perms, req.Permissions) {
				return s.rolePB(p, r), nil
			}
			return nil, status.Error(codes.Internal, "failed to create role")
		}
	}
	s.nextID++
	r := &roleRec{id: fmt.Sprintf("role-%d", s.nextID), name: req.Name, description: req.Description, perms: append([]string{}, req.Permissions...)}
	p.roles[r.id] = r
	return s.rolePB(p, r), nil
}

func (s *Server) GetRole(_ context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	r := p.roles[req.Id]
	if r == nil {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	return s.rolePB(p, r), nil
}

func (s *Server) UpdateRole(_ context.Context, req *pb.UpdateRoleRequest) (*pb.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	r := p.roles[req.Id]
	if r == nil {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if m := p.missingPerms(req.Permissions); len(m) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "specified permissions not found: %v", m)
	}
	s.log("UpdateRole %s", r.name)
	r.name, r.description, r.perms = req.Name, req.Description, append([]string{}, req.Permissions...)
	return s.rolePB(p, r), nil
}

func (s *Server) DeleteRole(_ context.Context, req *pb.DeleteRoleRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	r := p.roles[req.Id]
	if r == nil {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	// The real service fails to delete a role that still names a deleted permission.
	if m := p.missingPerms(r.perms); len(m) > 0 {
		return nil, status.Error(codes.Internal, "failed to delete role")
	}
	s.log("DeleteRole %s", r.name)
	delete(p.roles, req.Id)
	return &emptypb.Empty{}, nil
}

func (s *Server) ListRoles(_ context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	var all []*pb.Role
	for _, r := range p.roles {
		if req.GetSearch() == "" || strings.Contains(strings.ToLower(r.name), strings.ToLower(req.GetSearch())) {
			all = append(all, s.rolePB(p, r))
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Id < all[j].Id })
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListRolesResponse{Roles: items, Pagination: pg}, nil
}

// --- grants ---

func (s *Server) GrantUserPermissionsAndRolesOnResource(_ context.Context, req *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	if m := p.missingPerms(req.Permissions); len(m) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid permissions: %v", m)
	}
	for _, id := range req.Roles {
		if p.roles[id] == nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid roles: [%s]", id)
		}
	}
	if strings.HasPrefix(req.UserId, "group:") && p.groups[strings.TrimPrefix(req.UserId, "group:")] == nil {
		return nil, status.Errorf(codes.InvalidArgument, "group %q does not exist", req.UserId)
	}
	s.log("Grant %s %s roles=%v perms=%v", req.UserId, req.ResourceUri, req.Roles, req.Permissions)
	k := grantKey{req.UserId, req.ResourceUri}
	g := p.grants[k]
	if g == nil {
		g = &grant{perms: map[string]bool{}, roles: map[string]bool{}}
		p.grants[k] = g
	}
	for _, x := range req.Permissions {
		g.perms[x] = true
	}
	for _, x := range req.Roles {
		g.roles[x] = true
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) RevokeUserPermissionsAndRolesOnResource(_ context.Context, req *pb.RevokeUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	s.log("Revoke %s %s roles=%v perms=%v", req.UserId, req.ResourceUri, req.Roles, req.Permissions)
	k := grantKey{req.UserId, req.ResourceUri}
	if g := p.grants[k]; g != nil {
		for _, x := range req.Permissions {
			delete(g.perms, x)
		}
		for _, x := range req.Roles {
			delete(g.roles, x)
		}
		if len(g.perms) == 0 && len(g.roles) == 0 {
			delete(p.grants, k)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) GetUserPermissionsAndRolesOnResource(_ context.Context, req *pb.GetUserPermissionsAndRolesOnResourceRequest) (*pb.GetUserPermissionsAndRolesOnResourceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := &pb.GetUserPermissionsAndRolesOnResourceResponse{ProjectName: req.ProjectName, UserId: req.UserId, ResourceUri: req.ResourceUri, Permissions: []string{}, Roles: []string{}}
	if g := s.proj(req.ProjectName).grants[grantKey{req.UserId, req.ResourceUri}]; g != nil {
		res.Permissions, res.Roles = keys(g.perms), keys(g.roles)
	}
	return res, nil
}

func (s *Server) ListPrincipals(_ context.Context, req *pb.ListPrincipalsRequest) (*pb.ListPrincipalsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]bool{}
	for k := range s.proj(req.ProjectName).grants {
		if req.GetSearch() == "" || strings.Contains(strings.ToLower(k.principal), strings.ToLower(req.GetSearch())) {
			set[k.principal] = true
		}
	}
	items, pg, err := page(keys(set), req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListPrincipalsResponse{Principals: items, Pagination: pg}, nil
}

func (s *Server) GetAllAssignmentsForPrincipal(_ context.Context, req *pb.GetAllAssignmentsForPrincipalRequest) (*pb.GetAllAssignmentsForPrincipalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	var all []*pb.Assignment
	for k, g := range p.grants {
		if k.principal != req.PrincipalId {
			continue
		}
		a := &pb.Assignment{ResourceUri: k.uri}
		for _, name := range keys(g.perms) {
			if perm := p.perms[name]; perm != nil {
				a.Permissions = append(a.Permissions, perm)
			}
		}
		for _, id := range keys(g.roles) {
			if r := p.roles[id]; r != nil {
				a.Roles = append(a.Roles, s.rolePB(p, r))
			}
		}
		all = append(all, a)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ResourceUri < all[j].ResourceUri })
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.GetAllAssignmentsForPrincipalResponse{Assignments: items, Pagination: pg}, nil
}

// --- checks ---

func (s *Server) Check(_ context.Context, req *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	res := &pb.CheckPermissionResponse{Passed: true}
	for _, uri := range req.ResourceUris {
		held := p.held(req.PrincipalId, uri)
		var missing []string
		for _, perm := range req.Permissions {
			if !held[perm] {
				missing = append(missing, perm)
			}
		}
		if len(missing) > 0 {
			res.Passed = false
			res.MissingPermissions = append(res.MissingPermissions, &pb.MissingPermissions{ResourceUri: uri, MissingPermissions: missing})
		}
	}
	return res, nil
}

func (s *Server) BatchCheck(_ context.Context, req *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	res := &pb.BatchCheckResponse{}
	for _, uri := range req.ResourceUris {
		held := p.held(req.PrincipalId, uri)
		r := &pb.BatchCheckResult{ResourceUri: uri, Allowed: true}
		for _, perm := range req.Permissions {
			if !held[perm] {
				r.Allowed = false
				r.MissingPermissions = append(r.MissingPermissions, perm)
			}
		}
		res.Results = append(res.Results, r)
	}
	return res, nil
}

func (s *Server) ListAccess(_ context.Context, req *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	if p.held(req.PrincipalId, req.UnderUri)[req.Permission] {
		return &pb.ListAccessResponse{CoversAll: true, Scopes: []*pb.AccessScope{{Uri: req.UnderUri, Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE}}, Pagination: &paginationv1.PaginationResponse{}}, nil
	}
	principals := append([]string{req.PrincipalId}, p.groupsOf(req.PrincipalId)...)
	under := segs(req.UnderUri)
	set := map[string]bool{}
	for k, g := range p.grants {
		gs := segs(k.uri)
		if !contains(principals, k.principal) || len(gs) <= len(under) || !p.effective(g)[req.Permission] {
			continue
		}
		ok := true
		for i := range under {
			if gs[i] != "_" && gs[i] != under[i] {
				ok = false
				break
			}
		}
		if ok {
			set[k.uri] = true
		}
	}
	var scopes []*pb.AccessScope
	for _, uri := range keys(set) {
		kind := pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE
		if contains(segs(uri), "_") {
			kind = pb.AccessScopeKind_ACCESS_SCOPE_KIND_PATTERN
		}
		scopes = append(scopes, &pb.AccessScope{Uri: uri, Scope: kind})
	}
	items, pg, err := page(scopes, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListAccessResponse{Scopes: items, Pagination: pg}, nil
}

func (s *Server) ListPrincipalsWithAccess(_ context.Context, req *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	via := map[string][]*pb.AccessGrant{}
	for k, g := range p.grants {
		if !covers(k.uri, req.ResourceUri) {
			continue
		}
		match := pb.AccessGrantMatch_ACCESS_GRANT_MATCH_EXACT
		if k.uri != req.ResourceUri {
			match = pb.AccessGrantMatch_ACCESS_GRANT_MATCH_WILDCARD
			if len(segs(k.uri)) < len(segs(req.ResourceUri)) {
				match = pb.AccessGrantMatch_ACCESS_GRANT_MATCH_ANCESTOR
			}
		}
		inherited := match != pb.AccessGrantMatch_ACCESS_GRANT_MATCH_EXACT
		for _, id := range keys(g.roles) {
			r := p.roles[id]
			if r == nil || (req.Permission != nil && !contains(r.perms, *req.Permission)) {
				continue
			}
			via[k.principal] = append(via[k.principal], &pb.AccessGrant{ResourceUri: k.uri, Inherited: inherited, Match: match, Source: &pb.AccessGrant_Role{Role: &pb.AccessGrantRole{Id: r.id, Name: r.name}}})
		}
		if len(g.perms) > 0 && (req.Permission == nil || g.perms[*req.Permission]) {
			via[k.principal] = append(via[k.principal], &pb.AccessGrant{ResourceUri: k.uri, Inherited: inherited, Match: match, Source: &pb.AccessGrant_Direct{Direct: &pb.AccessGrantDirect{}}})
		}
	}
	var all []*pb.PrincipalAccess
	for principal, v := range via {
		sort.SliceStable(v, func(i, j int) bool { return len(v[i].ResourceUri) > len(v[j].ResourceUri) })
		isGroup := strings.HasPrefix(principal, "group:")
		all = append(all, &pb.PrincipalAccess{PrincipalId: principal, IsGroup: isGroup, Via: v})
		if isGroup && req.ExpandGroups {
			name := strings.TrimPrefix(principal, "group:")
			if g := p.groups[name]; g != nil {
				for m := range g.members {
					all = append(all, &pb.PrincipalAccess{PrincipalId: m, ViaGroup: name, Via: v})
				}
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].PrincipalId != all[j].PrincipalId {
			return all[i].PrincipalId < all[j].PrincipalId
		}
		return all[i].ViaGroup < all[j].ViaGroup
	})
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListPrincipalsWithAccessResponse{Principals: items, Pagination: pg}, nil
}

// --- groups ---

func (s *Server) CreateGroup(_ context.Context, req *pb.CreateGroupRequest) (*pb.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	if p.groups[req.Name] != nil {
		return nil, status.Error(codes.AlreadyExists, "a group with this name already exists in the project")
	}
	s.log("CreateGroup %s", req.Name)
	s.nextID++
	now := timestamppb.Now()
	g := &pb.Group{Id: fmt.Sprintf("group-%d", s.nextID), OrganisationId: orgID, ProjectName: req.ProjectName, Name: req.Name, Description: req.Description, PrincipalId: "group:" + req.Name, CreatedAt: now, UpdatedAt: now}
	p.groups[req.Name] = &group{pb: g, members: map[string]time.Time{}}
	return g, nil
}

func (s *Server) GetGroup(_ context.Context, req *pb.GetGroupRequest) (*pb.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.proj(req.ProjectName).groups[req.Name]
	if g == nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	return g.pb, nil
}

func (s *Server) UpdateGroup(_ context.Context, req *pb.UpdateGroupRequest) (*pb.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.proj(req.ProjectName).groups[req.Name]
	if g == nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	s.log("UpdateGroup %s", req.Name)
	g.pb.Description = req.Description
	g.pb.UpdatedAt = timestamppb.Now()
	return g.pb, nil
}

func (s *Server) DeleteGroup(_ context.Context, req *pb.DeleteGroupRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.proj(req.ProjectName)
	s.log("DeleteGroup %s", req.Name)
	delete(p.groups, req.Name)
	for k := range p.grants {
		if k.principal == "group:"+req.Name {
			delete(p.grants, k)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListGroups(_ context.Context, req *pb.ListGroupsRequest) (*pb.ListGroupsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*pb.Group
	for _, g := range s.proj(req.ProjectName).groups {
		if req.GetSearch() == "" || strings.Contains(g.pb.Name, req.GetSearch()) {
			all = append(all, g.pb)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListGroupsResponse{Groups: items, Pagination: pg}, nil
}

func (s *Server) AddGroupMembers(_ context.Context, req *pb.AddGroupMembersRequest) (*pb.AddGroupMembersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.proj(req.ProjectName).groups[req.Name]
	if g == nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	res := &pb.AddGroupMembersResponse{}
	for _, m := range req.PrincipalIds {
		if strings.HasPrefix(m, "group:") {
			return nil, status.Error(codes.InvalidArgument, "groups cannot contain groups")
		}
	}
	s.log("AddGroupMembers %s %v", req.Name, req.PrincipalIds)
	for _, m := range req.PrincipalIds {
		if _, ok := g.members[m]; ok {
			res.ExistingPrincipalIds = append(res.ExistingPrincipalIds, m)
			continue
		}
		g.members[m] = time.Now()
		res.AddedPrincipalIds = append(res.AddedPrincipalIds, m)
	}
	return res, nil
}

func (s *Server) RemoveGroupMembers(_ context.Context, req *pb.RemoveGroupMembersRequest) (*pb.RemoveGroupMembersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.proj(req.ProjectName).groups[req.Name]
	if g == nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	s.log("RemoveGroupMembers %s %v", req.Name, req.PrincipalIds)
	res := &pb.RemoveGroupMembersResponse{}
	for _, m := range req.PrincipalIds {
		if _, ok := g.members[m]; !ok {
			res.NotMemberPrincipalIds = append(res.NotMemberPrincipalIds, m)
			continue
		}
		delete(g.members, m)
		res.RemovedPrincipalIds = append(res.RemovedPrincipalIds, m)
	}
	return res, nil
}

func (s *Server) ListGroupMembers(_ context.Context, req *pb.ListGroupMembersRequest) (*pb.ListGroupMembersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.proj(req.ProjectName).groups[req.Name]
	if g == nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	var names []string
	for m := range g.members {
		names = append(names, m)
	}
	sort.Strings(names)
	var all []*pb.GroupMember
	for _, m := range names {
		all = append(all, &pb.GroupMember{PrincipalId: m, CreatedAt: timestamppb.New(g.members[m])})
	}
	items, pg, err := page(all, req.Pagination, s.DefaultPageSize, s.MaxPageSize)
	if err != nil {
		return nil, err
	}
	return &pb.ListGroupMembersResponse{Members: items, Pagination: pg}, nil
}

func sameSet(a, b []string) bool {
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	n := map[string]bool{}
	for _, x := range b {
		if !m[x] {
			return false
		}
		n[x] = true
	}
	return len(n) == len(m)
}
