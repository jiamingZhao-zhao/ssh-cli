package bundle

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"gopkg.in/yaml.v3"
)

// ApplyConfirmed checks the candidate against cfg, requires the same human
// phrase as group set-env and policy widen, then applies the bundle.
// The caller saves cfg (which signs) only after this returns nil, then
// records the audit line with confirmgate.RecordImport.
func ApplyConfirmed(dir, actor, phrase string, cfg *config.Config, data []byte) ([]confirmgate.Need, string, error) {
	next, err := preview(cfg, data)
	if err != nil {
		return nil, "", err
	}
	needs, err := confirmgate.ImportNeeds(dir, cfg, next)
	if err != nil {
		return nil, "", err
	}
	if err := confirmgate.Require(dir, actor, phrase, needs); err != nil {
		return nil, "", err
	}
	summary := confirmgate.DiffSummary(cfg, next)
	if err := Apply(cfg, data); err != nil {
		return nil, "", err
	}
	return needs, summary, nil
}

func preview(cfg *config.Config, data []byte) (*config.Config, error) {
	next, err := cloneConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err := Apply(next, data); err != nil {
		return nil, err
	}
	if err := next.Normalize(); err != nil {
		return nil, err
	}
	return next, nil
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	next := &config.Config{}
	if err := yaml.Unmarshal(raw, next); err != nil {
		return nil, err
	}
	if err := next.Normalize(); err != nil {
		return nil, err
	}
	return next, nil
}
