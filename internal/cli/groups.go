package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/perms-io/permio-cli/pkg/permio"
)

func (a *App) newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "groups",
		Aliases: []string{"group"},
		Short:   "Manage groups of principals and their members",
		Long: `A group is a named set of principals. Grant roles and permissions to the
principal "group:<slug>" and every member holds them. Slugs are 1-64
lower-case letters, digits and hyphens and cannot be changed. Groups cannot
contain groups. Writing needs a full-access key.`,
		Example: `  permio groups create design --description "Design team"
  permio groups members add design user_123 user_456
  permio grants add --principal group:design --resource /projects/7 --role editor`,
	}
	cmd.AddCommand(a.groupsList(), a.groupsGet(), a.groupsCreate(), a.groupsUpdate(), a.groupsDelete(), a.groupsMembers())
	return cmd
}

func (a *App) groupsList() *cobra.Command {
	var search string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every group in the project",
		Example: `  permio groups list --json`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			groups, err := c.ListGroups(cmd.Context(), search)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"groups": groups})
			}
			if a.quiet {
				for _, g := range groups {
					fmt.Fprintln(a.Stdout, g.Name)
				}
				return nil
			}
			if len(groups) == 0 {
				fmt.Fprintln(a.Stdout, "No groups.")
				return nil
			}
			w := a.table()
			fmt.Fprintln(w, "NAME\tPRINCIPAL\tDESCRIPTION")
			for _, g := range groups {
				fmt.Fprintf(w, "%s\t%s\t%s\n", g.Name, g.PrincipalID, orDash(g.Description))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&search, "search", "", "only groups whose name contains this text")
	return cmd
}

type groupWithMembers struct {
	permio.Group
	Members []string `json:"members"`
}

func (a *App) groupsGet() *cobra.Command {
	return &cobra.Command{
		Use:     "get <slug>",
		Short:   "Show a group and its members",
		Example: `  permio groups get design --json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			g, err := c.GetGroup(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			members, err := c.ListGroupMembers(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(groupWithMembers{Group: *g, Members: members})
			}
			fmt.Fprintf(a.Stdout, "Name:         %s\nPrincipal:    %s\nDescription:  %s\nMembers:      %s\n", g.Name, g.PrincipalID, orDash(g.Description), joinOrDash(members))
			return nil
		},
	}
}

func (a *App) groupsCreate() *cobra.Command {
	var description string
	var members []string
	cmd := &cobra.Command{
		Use:     "create <slug>",
		Short:   "Create a group",
		Example: `  permio groups create design --description "Design team" --member user_123 --member user_456`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			g, err := c.CreateGroup(cmd.Context(), args[0], description)
			if err != nil {
				return err
			}
			if len(members) > 0 {
				if _, err := c.AddGroupMembers(cmd.Context(), g.Name, members); err != nil {
					return fmt.Errorf("group created, but adding members failed: %w", err)
				}
			}
			if a.jsonOut {
				if members == nil {
					members = []string{}
				}
				return a.printJSON(groupWithMembers{Group: *g, Members: members})
			}
			a.info("Created group %s (grant to %s)", g.Name, g.PrincipalID)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "description")
	cmd.Flags().StringSliceVar(&members, "member", nil, "initial member principal ID (repeatable or comma-separated)")
	return cmd
}

func (a *App) groupsUpdate() *cobra.Command {
	var description string
	cmd := &cobra.Command{
		Use:     "update <slug> --description <text>",
		Short:   "Change a group's description",
		Example: `  permio groups update design --description "Product design team"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("description") {
				return usageErr("nothing to change: give --description (a group's slug cannot be changed)")
			}
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			g, err := c.UpdateGroup(cmd.Context(), args[0], description)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(g)
			}
			a.info("Updated group %s", g.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "new description")
	return cmd
}

func (a *App) groupsDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <slug...>",
		Short: "Delete groups with their memberships and grants",
		Long: `Delete groups. This also removes their memberships and every grant made to
group:<slug>. Deleting a group that does not exist succeeds.`,
		Example: `  permio groups delete design`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			for _, name := range args {
				if err := c.DeleteGroup(cmd.Context(), name); err != nil {
					return fmt.Errorf("deleting group %s: %w", name, err)
				}
				a.info("Deleted group %s", name)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"deleted": args})
			}
			return nil
		},
	}
}

func (a *App) groupsMembers() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "members",
		Aliases: []string{"member"},
		Short:   "List, add and remove group members",
		Example: `  permio groups members list design
  permio groups members add design user_123 user_456
  permio groups members remove design user_456`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "list <slug>",
		Aliases: []string{"ls"},
		Short:   "List a group's members",
		Example: `  permio groups members list design --json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			members, err := c.ListGroupMembers(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"group": args[0], "members": members})
			}
			if len(members) == 0 && !a.quiet {
				fmt.Fprintln(a.Stdout, "No members.")
			}
			for _, m := range members {
				fmt.Fprintln(a.Stdout, m)
			}
			return nil
		},
	})
	for _, add := range []bool{true, false} {
		add := add
		use, short, example := "add <slug> <principal...>", "Add principals to a group", "  permio groups members add design user_123 user_456"
		if !add {
			use, short, example = "remove <slug> <principal...>", "Remove principals from a group", "  permio groups members remove design user_456"
		}
		cmd.AddCommand(&cobra.Command{
			Use:     use,
			Short:   short,
			Example: example,
			Args:    cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, _, err := a.client("")
				if err != nil {
					return err
				}
				defer c.Close()
				var res *permio.MembershipChange
				if add {
					res, err = c.AddGroupMembers(cmd.Context(), args[0], args[1:])
				} else {
					res, err = c.RemoveGroupMembers(cmd.Context(), args[0], args[1:])
				}
				if err != nil {
					return err
				}
				if a.jsonOut {
					if add {
						return a.printJSON(map[string]any{"group": args[0], "added": res.Changed, "already_members": res.Unchanged})
					}
					return a.printJSON(map[string]any{"group": args[0], "removed": res.Changed, "not_members": res.Unchanged})
				}
				if add {
					a.info("Added %d member(s) to %s; %d already member(s)", len(res.Changed), args[0], len(res.Unchanged))
				} else {
					a.info("Removed %d member(s) from %s; %d were not members", len(res.Changed), args[0], len(res.Unchanged))
				}
				return nil
			},
		})
	}
	return cmd
}
