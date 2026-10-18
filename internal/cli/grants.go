package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

func (a *App) newGrantsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "grants",
		Aliases: []string{"grant"},
		Short:   "List, add and remove grants (roles and permissions on resources)",
		Long: `A grant gives a principal roles and/or permissions on a resource URI. It
applies to that URI and everything below it. Grant to a group with the
principal "group:<slug>". Adding and removing need a full-access key.`,
		Example: `  permio grants list --principal user_123
  permio grants add --principal user_123 --resource /documents/42 --role editor
  permio grants remove --principal user_123 --resource /documents/42 --permission document.delete`,
	}
	cmd.AddCommand(a.grantsList(), a.grantsAdd(), a.grantsRemove())
	return cmd
}

func (a *App) printGrants(grants []permio.Grant) error {
	if a.jsonOut {
		return a.printJSON(map[string]any{"grants": grants})
	}
	if len(grants) == 0 {
		if !a.quiet {
			fmt.Fprintln(a.Stdout, "No grants.")
		}
		return nil
	}
	if a.quiet {
		for _, g := range grants {
			fmt.Fprintf(a.Stdout, "%s\t%s\n", g.Principal, g.Resource)
		}
		return nil
	}
	w := a.table()
	fmt.Fprintln(w, "PRINCIPAL\tRESOURCE\tROLES\tPERMISSIONS")
	for _, g := range grants {
		var roles []string
		for _, r := range g.Roles {
			roles = append(roles, orDash(r.Name))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", g.Principal, g.Resource, joinOrDash(roles), joinOrDash(g.Permissions))
	}
	return w.Flush()
}

func (a *App) grantsList() *cobra.Command {
	var principal, resource string
	cmd := &cobra.Command{
		Use:     "list [--principal <id>] [--resource <uri>]",
		Aliases: []string{"ls"},
		Short:   "List grants by principal, by resource, or all of them",
		Long: `List grants made directly (not inherited):

  --principal P               every grant to P
  --resource R                every grant made on exactly R
  --principal P --resource R  P's grant on exactly R
  (neither)                   every grant in the project

Use 'permio access who' to include grants inherited from ancestors, wildcards
and groups.`,
		Example: `  permio grants list --principal user_123
  permio grants list --resource /documents/42 --json
  permio grants list`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if resource != "" {
				if err := permio.ValidateResourceURI(resource); err != nil {
					return err
				}
			}
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			ctx := cmd.Context()
			var grants []permio.Grant
			switch {
			case principal != "" && resource != "":
				roles, err := c.ListRoles(ctx, "")
				if err != nil {
					return err
				}
				g, err := c.GetGrant(ctx, principal, resource, roles)
				if err != nil {
					return err
				}
				grants = []permio.Grant{}
				if len(g.Roles) > 0 || len(g.Permissions) > 0 {
					grants = append(grants, *g)
				}
			case principal != "":
				grants, err = c.ListAssignments(ctx, principal)
			case resource != "":
				grants, err = grantsOnResource(ctx, c, resource)
			default:
				grants, err = c.ListAllGrants(ctx)
			}
			if err != nil {
				return err
			}
			return a.printGrants(grants)
		},
	}
	cmd.Flags().StringVar(&principal, "principal", "", "principal ID (users, services, or group:<slug>)")
	cmd.Flags().StringVar(&resource, "resource", "", "resource URI, e.g. /documents/42")
	return cmd
}

// grantsOnResource finds the grants made on exactly resource: principals come
// from ListPrincipalsWithAccess, their exact grants from GetUserPermissionsAndRolesOnResource.
func grantsOnResource(ctx context.Context, c *permio.Client, resource string) ([]permio.Grant, error) {
	entries, err := c.WhoHasAccess(ctx, resource, "", false)
	if err != nil {
		return nil, err
	}
	roles, err := c.ListRoles(ctx, "")
	if err != nil {
		return nil, err
	}
	out := []permio.Grant{}
	seen := map[string]bool{}
	for _, e := range entries {
		exact := false
		for _, v := range e.Via {
			if v.Resource == resource {
				exact = true
			}
		}
		if !exact || seen[e.Principal] || e.ViaGroup != "" {
			continue
		}
		seen[e.Principal] = true
		g, err := c.GetGrant(ctx, e.Principal, resource, roles)
		if err != nil {
			return nil, err
		}
		if len(g.Roles) > 0 || len(g.Permissions) > 0 {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal < out[j].Principal })
	return out, nil
}

type grantFlags struct {
	principal, resource string
	roles, perms        []string
}

func (g *grantFlags) register(cmd *cobra.Command, verb string) {
	cmd.Flags().StringVar(&g.principal, "principal", "", "principal ID (required); group:<slug> for a group")
	cmd.Flags().StringVar(&g.resource, "resource", "", "resource URI (required), e.g. /documents/42")
	cmd.Flags().StringSliceVarP(&g.roles, "role", "r", nil, "role ID or name to "+verb+" (repeatable or comma-separated)")
	cmd.Flags().StringSliceVarP(&g.perms, "permission", "p", nil, "permission to "+verb+" (repeatable or comma-separated)")
	_ = cmd.MarkFlagRequired("principal")
	_ = cmd.MarkFlagRequired("resource")
}

func resolveRoleIDs(roles []permio.Role, refs []string) ([]permio.RoleRef, error) {
	out := []permio.RoleRef{}
	for _, ref := range refs {
		r, err := permio.FindRole(roles, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, permio.RoleRef{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

func ids(refs []permio.RoleRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.ID
	}
	return out
}

type grantChangeOutput struct {
	Principal   string           `json:"principal"`
	Resource    string           `json:"resource"`
	Roles       []permio.RoleRef `json:"roles"`
	Permissions []string         `json:"permissions"`
	// Grant is the principal's grant on the resource after the change.
	Grant *permio.Grant `json:"grant"`
}

func (a *App) grantsAdd() *cobra.Command {
	var g grantFlags
	cmd := &cobra.Command{
		Use:   "add --principal <id> --resource <uri> [--role <r>...] [--permission <p>...]",
		Short: "Grant roles and/or permissions to a principal on a resource",
		Long: `Grant roles and/or permissions. Grants are additive: nothing already granted
is removed. Roles may be given by ID or exact name. Granting to group:<slug>
requires the group to exist.`,
		Example: `  permio grants add --principal user_123 --resource /documents/42 --role editor
  permio grants add --principal group:design --resource /projects/7 -r viewer -p comment.create
  permio grants add --principal user_123 --resource '/tenants/acme/projects/_' --role viewer`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.changeGrant(cmd.Context(), g, true)
		},
	}
	g.register(cmd, "grant")
	return cmd
}

func (a *App) grantsRemove() *cobra.Command {
	var g grantFlags
	var all bool
	cmd := &cobra.Command{
		Use:     "remove --principal <id> --resource <uri> [--role <r>...] [--permission <p>...] [--all]",
		Aliases: []string{"revoke"},
		Short:   "Revoke roles and/or permissions from a principal on a resource",
		Long: `Revoke roles and/or permissions from the grant on exactly this resource.
--all revokes everything the principal has on it. Grants inherited from other
URIs are not affected.`,
		Example: `  permio grants remove --principal user_123 --resource /documents/42 --role editor
  permio grants remove --principal user_123 --resource /documents/42 --all`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(g.roles) > 0 || len(g.perms) > 0 {
					return usageErr("--all cannot be combined with --role or --permission")
				}
				c, _, err := a.client("")
				if err != nil {
					return err
				}
				defer c.Close()
				cur, err := c.GetGrant(cmd.Context(), g.principal, g.resource, nil)
				if err != nil {
					return err
				}
				g.roles = ids(cur.Roles)
				g.perms = cur.Permissions
				if len(g.roles) == 0 && len(g.perms) == 0 {
					if a.jsonOut {
						return a.printJSON(grantChangeOutput{Principal: g.principal, Resource: g.resource, Roles: []permio.RoleRef{}, Permissions: []string{}, Grant: cur})
					}
					a.info("Nothing to revoke: %s has no grant on %s", g.principal, g.resource)
					return nil
				}
			}
			return a.changeGrant(cmd.Context(), g, false)
		},
	}
	g.register(cmd, "revoke")
	cmd.Flags().BoolVar(&all, "all", false, "revoke every role and permission on this resource")
	return cmd
}

func (a *App) changeGrant(ctx context.Context, g grantFlags, add bool) error {
	if len(g.roles) == 0 && len(g.perms) == 0 {
		return usageErr("give at least one --role or --permission")
	}
	if err := permio.ValidateResourceURI(g.resource); err != nil {
		return err
	}
	c, _, err := a.client("")
	if err != nil {
		return err
	}
	defer c.Close()
	roles, err := c.ListRoles(ctx, "")
	if err != nil {
		return err
	}
	refs, err := resolveRoleIDs(roles, g.roles)
	if err != nil {
		return err
	}
	verb := "Granted"
	if add {
		err = c.Grant(ctx, g.principal, g.resource, ids(refs), g.perms)
	} else {
		verb = "Revoked"
		err = c.Revoke(ctx, g.principal, g.resource, ids(refs), g.perms)
	}
	if err != nil {
		return err
	}
	after, err := c.GetGrant(ctx, g.principal, g.resource, roles)
	if err != nil {
		return err
	}
	if a.jsonOut {
		perms := g.perms
		if perms == nil {
			perms = []string{}
		}
		return a.printJSON(grantChangeOutput{Principal: g.principal, Resource: g.resource, Roles: refs, Permissions: perms, Grant: after})
	}
	var parts []string
	for _, r := range refs {
		parts = append(parts, "role "+r.Name)
	}
	parts = append(parts, g.perms...)
	prep := "to"
	if !add {
		prep = "from"
	}
	a.info("%s %s %s %s on %s", verb, strings.Join(parts, ", "), prep, g.principal, g.resource)
	return nil
}
