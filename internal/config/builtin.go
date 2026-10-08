package config

// BuiltinEnvNames are the env labels every config has. They cannot be added,
// edited, or removed. Other env names are custom and can be maintained.
func BuiltinEnvNames() []string {
	return []string{"dev", "test", "preprod", "prod"}
}

// IsBuiltinEnv reports whether name is one of the four locked env labels.
func IsBuiltinEnv(name string) bool {
	_, ok := builtinEnv(name)
	return ok
}

// BuiltinEnv returns the canonical definition of a locked env label.
func BuiltinEnv(name string) (Env, bool) {
	env, ok := builtinEnv(name)
	return env, ok
}

func builtinEnv(name string) (Env, bool) {
	switch name {
	case "dev":
		return Env{Label: "开发", Color: "green", MaxMode: ModeAdmin, DefaultPolicy: "standard"}, true
	case "test":
		return Env{Label: "测试", Color: "yellow", MaxMode: ModeStandard, DefaultPolicy: "standard"}, true
	case "preprod":
		return Env{Label: "预生产", Color: "orange", MaxMode: ModeStandard, DefaultPolicy: "standard"}, true
	case "prod":
		return Env{Label: "生产", Color: "red", MaxMode: ModeReadonly, DefaultPolicy: "readonly"}, true
	default:
		return Env{}, false
	}
}

// ensureBuiltinEnvs inserts any missing built-in env and resets the locked
// fields (label, color, maxMode, defaultPolicy). breakGlass and noDataOutflow
// already stored on that env are kept.
func (c *Config) ensureBuiltinEnvs() {
	if c.Envs == nil {
		c.Envs = map[string]*Env{}
	}
	for _, name := range BuiltinEnvNames() {
		canon, _ := builtinEnv(name)
		cur := c.Envs[name]
		if cur == nil {
			cp := canon
			c.Envs[name] = &cp
			continue
		}
		cur.Label = canon.Label
		cur.Color = canon.Color
		cur.MaxMode = canon.MaxMode
		cur.DefaultPolicy = canon.DefaultPolicy
	}
}
