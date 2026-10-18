package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

func (a *App) newAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Ask where a principal has access, or who has access to a resource",
		Long: `Access queries count grants made directly, through roles, through groups,
on ancestors and through "_" wildcard URIs:

  access list  where may principal P use permission X at or below URI U?
  access who   which principals have access to resource R?`,
		Example: `  permio access list --principal user_123 --permission document.read --under /documents
  permio access who --resource /documents/42 --permission document.read --expand-groups`,
	}
	cmd.AddCommand(a.accessList(), a.accessWho())
	return cmd
}

type accessListOutput struct {
	*permio.AccessScopes
	Principal  string        `json:"principal"`
	Permission string        `json:"permission"`
	Prefixes   []string      `json:"prefixes"`
	Patterns   []string      `json:"patterns"`
	Allows     []allowResult `json:"allows,omitempty"`
}

type allowResult struct {
	Resource string `json:"resource"`
	Allowed  bool   `json:"allowed"`
}

func (a *App) accessList() *cobra.Command {
	var principal, permission, under string
	var allows []string
	cmd := &cobra.Command{
		Use:   "list --principal <id> --permission <name> --under <uri> [--allows <uri>...]",
		Short: "List the scopes where a principal holds a permission",
		Long: `List the places at or below --under where the principal holds the permission.

covers_all=true means the principal holds it on --under itself and so on
everything below. Otherwise each scope is either a subtree (the URI and
everything below it) or a pattern (a URI with "_" segments, each matching one
segment). "prefixes" are the subtree URIs with covered ones removed, for
filtering a database by path prefix; "patterns" cannot be expressed as prefixes.

--allows tests URIs against the scopes locally; the exit code is then 0 if every
URI is allowed and 1 otherwise. A URI outside --under is never allowed by this
test (it was not asked about).`,
		Example: `  permio access list --principal user_123 --permission document.read --under /documents
  permio access list --principal user_123 --permission document.read --under /documents --allows /documents/42 --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			scopes, err := c.ListAccess(cmd.Context(), principal, permission, under)
			if err != nil {
				return err
			}
			out := accessListOutput{AccessScopes: scopes, Principal: principal, Permission: permission, Prefixes: scopes.Prefixes(), Patterns: scopes.Patterns()}
			allAllowed := true
			for _, u := range allows {
				ok := scopes.Allows(u)
				allAllowed = allAllowed && ok
				out.Allows = append(out.Allows, allowResult{Resource: u, Allowed: ok})
			}
			switch {
			case a.jsonOut:
				if err := a.printJSON(out); err != nil {
					return err
				}
			case a.quiet:
			default:
				switch {
				case scopes.CoversAll:
					fmt.Fprintf(a.Stdout, "%s has %s on all of %s\n", principal, permission, under)
				case len(scopes.Scopes) == 0:
					fmt.Fprintf(a.Stdout, "%s has %s nowhere under %s\n", principal, permission, under)
				default:
					fmt.Fprintf(a.Stdout, "%s has %s under %s on:\n", principal, permission, under)
					w := a.table()
					for _, s := range scopes.Scopes {
						fmt.Fprintf(w, "  %s\t%s\n", s.URI, s.Kind)
					}
					w.Flush()
				}
				for _, r := range out.Allows {
					result := "allowed"
					if !r.Allowed {
						result = "denied"
					}
					fmt.Fprintf(a.Stdout, "%s: %s\n", r.Resource, result)
				}
			}
			if len(allows) > 0 && !allAllowed {
				return denied()
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&principal, "principal", "", "principal ID (required)")
	f.StringVar(&permission, "permission", "", "permission name (required)")
	f.StringVar(&under, "under", "", "only consider resources at or below this URI (required)")
	f.StringSliceVar(&allows, "allows", nil, "test whether these URIs are covered (repeatable or comma-separated)")
	_ = cmd.MarkFlagRequired("principal")
	_ = cmd.MarkFlagRequired("permission")
	_ = cmd.MarkFlagRequired("under")
	return cmd
}

func (a *App) accessWho() *cobra.Command {
	var resource, permission string
	var expand bool
	cmd := &cobra.Command{
		Use:   "who --resource <uri> [--permission <name>] [--expand-groups]",
		Short: "List the principals with access to a resource",
		Long: `List the principals with a grant on the resource, on an ancestor of it, or on
a "_" wildcard URI matching it, with the grants that give the access. With
--permission, only grants that confer it count. Groups are listed as
group:<slug>; --expand-groups also lists their members (via_group is set).`,
		Example: `  permio access who --resource /documents/42
  permio access who --resource /documents/42 --permission document.edit --expand-groups --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			entries, err := c.WhoHasAccess(cmd.Context(), resource, permission, expand)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"resource": resource, "permission": permission, "principals": entries})
			}
			if a.quiet {
				for _, e := range entries {
					fmt.Fprintln(a.Stdout, e.Principal)
				}
				return nil
			}
			if len(entries) == 0 {
				fmt.Fprintln(a.Stdout, "Nobody.")
				return nil
			}
			w := a.table()
			fmt.Fprintln(w, "PRINCIPAL\tVIA GROUP\tGRANT ON\tMATCH\tSOURCE")
			for _, e := range entries {
				for i, v := range e.Via {
					p, g := e.Principal, orDash(e.ViaGroup)
					if i > 0 {
						p, g = "", ""
					}
					src := v.Source
					if v.Source == "role" {
						src = "role " + v.RoleName
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p, g, v.Resource, v.Match, src)
				}
			}
			return w.Flush()
		},
	}
	f := cmd.Flags()
	f.StringVar(&resource, "resource", "", "resource URI (required)")
	f.StringVar(&permission, "permission", "", "only count grants that confer this permission")
	f.BoolVar(&expand, "expand-groups", false, "also list members of groups with access")
	_ = cmd.MarkFlagRequired("resource")
	return cmd
}
