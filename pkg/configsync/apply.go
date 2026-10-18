package configsync

import (
	"context"
	"fmt"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

// Result reports what Apply did.
type Result struct {
	Project string   `json:"project"`
	Applied []Change `json:"applied"`
	Summary Summary  `json:"summary"`
}

// ApplyError is returned when a change fails. Changes before it were applied.
type ApplyError struct {
	Change Change
	Err    error
}

func (e *ApplyError) Error() string {
	return fmt.Sprintf("%s failed: %v", e.Change.Describe(), e.Err)
}

func (e *ApplyError) Unwrap() error { return e.Err }

// Apply executes plan against the project. cur must be the state the plan was
// computed from. progress, if set, is called after each change succeeds. It
// stops at the first failure and returns the partial result with an
// *ApplyError.
func Apply(ctx context.Context, c *permio.Client, plan *Plan, cur *State, progress func(Change)) (*Result, error) {
	res := &Result{Project: plan.Project, Applied: []Change{}}
	// Role name -> ID, updated as roles are created.
	roleIDs := map[string]string{}
	for id, r := range cur.Roles {
		roleIDs[r.Name] = id
		roleIDs[id] = id
	}
	done := func(ch Change) {
		res.Applied = append(res.Applied, ch)
		switch ch.Action {
		case Create:
			res.Summary.Create++
		case Update:
			res.Summary.Update++
		case Delete:
			res.Summary.Delete++
		}
		if progress != nil {
			progress(ch)
		}
	}
	for i := 0; i < len(plan.Changes); i++ {
		ch := plan.Changes[i]
		if err := ctx.Err(); err != nil {
			return res, &ApplyError{Change: ch, Err: err}
		}
		var err error
		switch ch.Kind {
		case KindPermission:
			switch ch.Action {
			case Create:
				_, err = c.CreatePermission(ctx, ch.Name, ch.description)
			case Update:
				_, err = c.UpdatePermission(ctx, ch.Name, "", ch.description)
			case Delete:
				err = c.DeletePermission(ctx, ch.Name)
			}
		case KindRole:
			switch ch.Action {
			case Create:
				var r *permio.Role
				r, err = c.CreateRole(ctx, ch.Name, ch.description, ch.finalPerms)
				if err == nil {
					roleIDs[ch.Name] = r.ID
				}
			case Update:
				_, err = c.UpdateRole(ctx, ch.RoleID, ch.Name, ch.description, ch.finalPerms)
			case Delete:
				err = c.DeleteRole(ctx, ch.RoleID)
			}
		case KindGroup:
			switch ch.Action {
			case Create:
				_, err = c.CreateGroup(ctx, ch.Name, ch.description)
			case Update:
				_, err = c.UpdateGroup(ctx, ch.Name, ch.description)
			case Delete:
				err = c.DeleteGroup(ctx, ch.Name)
			}
		case KindMember:
			// Batch consecutive changes to the same group's membership.
			batch := []Change{ch}
			for i+1 < len(plan.Changes) {
				next := plan.Changes[i+1]
				if next.Kind != KindMember || next.Group != ch.Group || next.Action != ch.Action {
					break
				}
				batch = append(batch, next)
				i++
			}
			principals := make([]string, len(batch))
			for j, b := range batch {
				principals[j] = b.Principal
			}
			if ch.Action == Create {
				_, err = c.AddGroupMembers(ctx, ch.Group, principals)
			} else {
				_, err = c.RemoveGroupMembers(ctx, ch.Group, principals)
			}
			if err != nil {
				return res, &ApplyError{Change: ch, Err: err}
			}
			for _, b := range batch {
				done(b)
			}
			continue
		case KindGrant:
			var add []string
			for _, ref := range ch.addRoleRefs {
				id, ok := roleIDs[ref]
				if !ok {
					err = fmt.Errorf("role %q has no ID", ref)
					break
				}
				add = append(add, id)
			}
			if err == nil && (len(add) > 0 || len(ch.AddPermissions) > 0) {
				err = c.Grant(ctx, ch.Principal, ch.Resource, add, ch.AddPermissions)
			}
			if err == nil && (len(ch.removeRoleIDs) > 0 || len(ch.RemovePermissions) > 0) {
				err = c.Revoke(ctx, ch.Principal, ch.Resource, ch.removeRoleIDs, ch.RemovePermissions)
			}
		}
		if err != nil {
			return res, &ApplyError{Change: ch, Err: err}
		}
		done(ch)
	}
	return res, nil
}
