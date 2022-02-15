// Copyright 2021 Allstar Authors

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package publiic implements the public repository policy.
package public

import (
	"context"

	"github.com/ossf/allstar/pkg/config"
	"github.com/ossf/allstar/pkg/policydef"

	"github.com/google/go-github/v39/github"
	"github.com/rs/zerolog/log"
)

const configFile = "public.yaml"
const polName = "public"

const notifyText = `The public repository is missing either a trusted admin or maintainer team.`

// OrgConfig is the org-level config definition for Public Repos.
type OrgConfig struct {
	// OptConfig is the standard org-level opt in/out config, RepoOverride applies to all
	// BP config.
	OptConfig config.OrgOptConfig `yaml:"optConfig"`

	// Action defines which action to take, default log, other: issue...
	Action string `yaml:"action"`

	// TrustedAdminTeams that are expected to be set as admin on public repos
	TrustedAdminTeams []string `yaml:"trustedAdminTeams"`

	// TrustedMaintainTeams that are expected to be set as maintainers on public repos
	TrustedMaintainTeams []string `yaml:"trustedMaintainTeams"`
}

// RepoConfig is the repo-level config for Branch Protection
type RepoConfig struct {
	// OptConfig is the standard repo-level opt in/out config.
	OptConfig config.RepoOptConfig `yaml:"optConfig"`

	// Action overrides the same setting in org-level, only if present.
	Action *string `yaml:"action"`

	// TrustedAdminTeams that are expected to be set as admin on public repos
	TrustedAdminTeams []string `yaml:"trustedAdminTeams"`

	// TrustedMaintainTeams that are expected to be set as maintainers on public repos
	TrustedMaintainTeams []string `yaml:"trustedMaintainTeams"`
}

type mergedConfig struct {
	Action               string
	TrustedAdminTeams    []string
	TrustedMaintainTeams []string
}

type details struct {
	Enabled              bool
	TrustedAdminTeams    []string
	TrustedMaintainTeams []string
}

var configFetchConfig func(context.Context, *github.Client, string, string, string, bool, interface{}) error

var configIsEnabled func(ctx context.Context, o config.OrgOptConfig, r config.RepoOptConfig, c *github.Client, owner, repo string) (bool, error)

func init() {
	configFetchConfig = config.FetchConfig
	configIsEnabled = config.IsEnabled
}

type v4client interface {
	Query(context.Context, interface{}, map[string]interface{}) error
}

// Public is the public policy object, implements policydef.Policy.
type Public bool

// NewPublic returns a new public policy.
func NewPublic() policydef.Policy {
	var s Public
	return s
}

// Name returns the name of this policy, implementing policydef.Policy.Name()
func (s Public) Name() string {
	return polName
}

type repositories interface {
	Get(context.Context, string, string) (*github.Repository,
		*github.Response, error)
	ListCollaborators(context.Context, string, string,
		*github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error)
	ListTeams(context.Context, string, string, *github.ListOptions) (
		[]*github.Team, *github.Response, error)
	AddCollaborator(context.Context, string, string, string,
		*github.RepositoryAddCollaboratorOptions) (*github.CollaboratorInvitation, *github.Response, error)
}

// Check performs the polcy check for public policy based on the
// configuration stored in the org/repo, implementing policydef.Policy.Check()
func (s Public) Check(ctx context.Context, c *github.Client, owner,
	repo string) (*policydef.Result, error) {

	return check(ctx, c.Repositories, c, owner, repo)
}

func check(ctx context.Context, rep repositories, c *github.Client, owner,
	repo string) (*policydef.Result, error) {
	oc, rc := getConfig(ctx, c, owner, repo)
	enabled, err := configIsEnabled(ctx, oc.OptConfig, rc.OptConfig, c, owner, repo)
	if err != nil {
		return nil, err
	}
	log.Info().
		Str("org", owner).
		Str("repo", repo).
		Str("area", polName).
		Bool("enabled", enabled).
		Msg("Check repo enabled")

	// only run on public repo
	gr, _, err := c.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	if gr.GetPrivate() {
		return &policydef.Result{
			Enabled:    false,
			Pass:       true,
			NotifyText: "Disabled",
			Details:    details{},
		}, nil
	}

	mc := mergeConfig(oc, rc, repo)
	admins, maintainers, err := getUsers(ctx, rep, owner, repo)
	if err != nil {
		return nil, err
	}

	var trustedAdmins []string
	var trustedMaintainers []string
	// check that at least one trusted admin team is an admin
	// this will typically be the open source team
	for _, admin := range admins {
		for _, tcs := range mc.TrustedAdminTeams {
			if admin == tcs {
				trustedAdmins = append(trustedAdmins, tcs)
			}
		}
	}
	for _, maintainer := range maintainers {
		for _, tcs := range mc.TrustedMaintainTeams {
			if maintainer == tcs {
				trustedMaintainers = append(trustedMaintainers, tcs)
			}
		}
	}

	if len(trustedAdmins) == 0 || len(trustedMaintainers) == 0 {
		return &policydef.Result{
			Enabled:    enabled,
			Pass:       false,
			NotifyText: notifyText,
			Details:    details{Enabled: true, TrustedAdminTeams: trustedAdmins, TrustedMaintainTeams: trustedMaintainers},
		}, nil
	}
	return &policydef.Result{
		Enabled:    enabled,
		Pass:       true,
		NotifyText: "",
		Details:    details{Enabled: true, TrustedAdminTeams: trustedAdmins, TrustedMaintainTeams: trustedMaintainers},
	}, nil
}

func getUsers(ctx context.Context, r repositories, owner, repo string) ([]string, []string, error) {
	opt := &github.ListCollaboratorsOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		Affiliation: "direct",
	}
	var users []*github.User
	for {
		us, resp, err := r.ListCollaborators(ctx, owner, repo, opt)
		if err != nil {
			return nil, nil, err
		}
		users = append(users, us...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	var adminUsers []string
	var maintainUsers []string
	for _, u := range users {
		if u.GetPermissions()["admin"] {
			adminUsers = append(adminUsers, u.GetLogin())
		} else if u.GetPermissions()["maintainer"] {
			maintainUsers = append(maintainUsers, u.GetLogin())
		}
	}
	return adminUsers, maintainUsers, nil
}

// Fix implementing policydef.Policy.Fix().
func (s Public) Fix(ctx context.Context, c *github.Client, owner, repo string) error {
	return fix(ctx, c.Repositories, c, owner, repo)
}

func fix(ctx context.Context, rep repositories, c *github.Client,
	owner, repo string) error {
	oc, rc := getConfig(ctx, c, owner, repo)
	enabled, err := configIsEnabled(ctx, oc.OptConfig, rc.OptConfig, c, owner, repo)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	mc := mergeConfig(oc, rc, repo)

	admins, maintainers, err := getUsers(ctx, rep, owner, repo)
	if err != nil {
		return err
	}

	// check that at least one trusted admin team is an admin
	// this will typically be the open source team
	for _, tcs := range mc.TrustedAdminTeams {
		isSet := false // the TrustedAdmin is not present
		for _, admin := range admins {
			if admin == tcs {
				isSet = true
				break
			}
		}
		if !isSet { // TrustedAdmin is not present, add them
			_, _, err := rep.AddCollaborator(ctx, owner, repo, tcs, &github.RepositoryAddCollaboratorOptions{Permission: "admin"})
			if err != nil {
				log.Error().Str("org", owner).
					Str("repo", repo).
					Str("user", tcs).
					Str("area", polName).
					Str("file", configFile).
					Err(err).
					Msg("Unexpected error adding new admin.")
			}
		}
	}
	for _, tcs := range mc.TrustedMaintainTeams {
		isSet := false // the TrustedMaintainer is not present
		for _, maintainer := range maintainers {
			if maintainer == tcs {
				isSet = true
				break
			}
		}
		if !isSet { // TrustedMaintainers is not present, add them
			_, _, err := rep.AddCollaborator(ctx, owner, repo, tcs, &github.RepositoryAddCollaboratorOptions{Permission: "maintain"})
			if err != nil {
				log.Error().Str("org", owner).
					Str("repo", repo).
					Str("user", tcs).
					Str("area", polName).
					Str("file", configFile).
					Err(err).
					Msg("Unexpected error adding new maintainer.")
			}
		}
	}
	return nil
}

// GetAction returns the configured action from public policy's
// configuration stored in the org-level repo, default log. Implementing
// policydef.Policy.GetAction()
func (s Public) GetAction(ctx context.Context, c *github.Client, owner, repo string) string {
	oc, rc := getConfig(ctx, c, owner, repo)
	mc := mergeConfig(oc, rc, repo)
	return mc.Action
}

func getConfig(ctx context.Context, c *github.Client, owner, repo string) (*OrgConfig, *RepoConfig) {
	oc := &OrgConfig{ // Fill out non-zero defaults
		Action: "log",
	}
	if err := configFetchConfig(ctx, c, owner, "", configFile, true, oc); err != nil {
		log.Error().
			Str("org", owner).
			Str("repo", repo).
			Bool("orgLevel", true).
			Str("area", polName).
			Str("file", configFile).
			Err(err).
			Msg("Unexpected config error, using defaults.")
	}
	rc := &RepoConfig{}
	if err := configFetchConfig(ctx, c, owner, repo, configFile, false, rc); err != nil {
		log.Error().
			Str("org", owner).
			Str("repo", repo).
			Bool("orgLevel", false).
			Str("area", polName).
			Str("file", configFile).
			Err(err).
			Msg("Unexpected config error, using defaults.")
	}
	return oc, rc
}

func mergeConfig(oc *OrgConfig, rc *RepoConfig, repo string) *mergedConfig {
	mc := &mergedConfig{
		Action: oc.Action,
	}

	if !oc.OptConfig.DisableRepoOverride {
		if rc.Action != nil {
			mc.Action = *rc.Action
		}
	}
	return mc
}
