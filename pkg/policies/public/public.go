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
}

type teams interface {
	AddTeamRepoBySlug(context.Context, string, string, string, string,
		*github.TeamAddTeamRepoOptions) (*github.Response, error)
	IsTeamRepoBySlug(context.Context, string, string, string, string) (*github.Repository, *github.Response, error)
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

	var trustedAdmins []string
	var trustedMaintainers []string

	// check that at all trusted admin teams are admins
	// this will typically be the open source team
	for _, tcs := range mc.TrustedAdminTeams {
		hasRole, err := teamHasRepoRole(ctx, c.Teams, owner, tcs, owner, repo, "admin")
		if err != nil {
			log.Error().Str("org", owner).
				Str("repo", repo).
				Str("team", tcs).
				Str("area", polName).
				Err(err).
				Msg("Unexpected error looking up team.")
		}
		if hasRole {
			trustedAdmins = append(trustedAdmins, tcs)
		}
	}

	for _, tcs := range mc.TrustedAdminTeams {
		hasRole, err := teamHasRepoRole(ctx, c.Teams, owner, tcs, owner, repo, "maintain")
		if err != nil {
			log.Error().Str("org", owner).
				Str("repo", repo).
				Str("team", tcs).
				Str("area", polName).
				Err(err).
				Msg("Unexpected error looking up team.")
		}
		if hasRole {
			trustedMaintainers = append(trustedMaintainers, tcs)
		}
	}

	if len(trustedAdmins) != len(mc.TrustedAdminTeams) || len(trustedMaintainers) != len(mc.TrustedMaintainTeams) {
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

func teamHasRepoRole(ctx context.Context, t teams, org, slug, owner, repo, role string) (bool, error) {

	r, resp, err := t.IsTeamRepoBySlug(ctx, org, slug, owner, repo)
	if err != nil {
		// check if the error is because the team does not have access to the repo
		if resp != nil && resp.StatusCode == 404 {
			return false, nil
		}
		return false, err
	}

	// whether the team has membership to the repo and the requested role
	return r.Permissions[role], nil
}

// Fix implementing policydef.Policy.Fix().
func (s Public) Fix(ctx context.Context, c *github.Client, owner, repo string) error {
	return fix(ctx, c.Repositories, c.Teams, c, owner, repo)
}

func fix(ctx context.Context, rep repositories, team teams, c *github.Client,
	owner, repo string) error {

	log.Info().
		Str("org", owner).
		Str("repo", repo).
		Str("area", polName).
		Bool("enabled", true).
		Msg("Fix")

	oc, rc := getConfig(ctx, c, owner, repo)
	mc := mergeConfig(oc, rc, repo)

	for _, slug := range mc.TrustedAdminTeams {
		// we can just add directly here, no need to check if already a member
		// since the GitHub api handles this and just returns a 204
		_, err := team.AddTeamRepoBySlug(ctx, owner, slug, owner, repo, &github.TeamAddTeamRepoOptions{Permission: "admin"})
		if err != nil {
			log.Error().Str("org", owner).
				Str("repo", repo).
				Str("user", slug).
				Str("area", polName).
				Str("file", configFile).
				Err(err).
				Msg("Unexpected error adding new admin.")
		}

	}
	for _, slug := range mc.TrustedMaintainTeams {
		// we can just add directly here, no need to check if already a member
		// since the GitHub api handles this and just returns a 204
		_, err := team.AddTeamRepoBySlug(ctx, owner, slug, owner, repo, &github.TeamAddTeamRepoOptions{Permission: "maintain"})
		if err != nil {
			log.Error().Str("org", owner).
				Str("repo", repo).
				Str("user", slug).
				Str("area", polName).
				Str("file", configFile).
				Err(err).
				Msg("Unexpected error adding new maintainer.")
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
		Action:               oc.Action,
		TrustedAdminTeams:    oc.TrustedAdminTeams,
		TrustedMaintainTeams: oc.TrustedMaintainTeams,
	}

	if !oc.OptConfig.DisableRepoOverride {
		if rc.Action != nil {
			mc.Action = *rc.Action
		}
	}
	return mc
}
