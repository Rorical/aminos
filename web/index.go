package web

import (
	"github.com/a-h/templ"

	"github.com/TecharoHQ/anubis/lib/policy/config"
)

func Base(title string, body templ.Component) templ.Component {
	return base(title, body, nil, nil)
}

func BaseWithChallengeAndOGTags(title string, body templ.Component, challenge string, rules *config.ChallengeRules, ogTags map[string]string) (templ.Component, error) {
	return base(title, body, struct {
		Rules     *config.ChallengeRules `json:"rules"`
		Challenge string                 `json:"challenge"`
	}{
		Challenge: challenge,
		Rules:     rules,
	}, ogTags), nil
}

// BaseWithChallengeAndMining creates a component that includes mining data
func BaseWithChallengeAndMining(title string, body templ.Component, challenge string, rules *config.ChallengeRules, mining bool, miningJob interface{}, ogTags map[string]string) (templ.Component, error) {
	return base(title, body, struct {
		Rules     *config.ChallengeRules `json:"rules"`
		Challenge string                 `json:"challenge"`
		Mining    bool                   `json:"mining"`
		MiningJob interface{}            `json:"mining_job,omitempty"`
	}{
		Challenge: challenge,
		Rules:     rules,
		Mining:    mining,
		MiningJob: miningJob,
	}, ogTags), nil
}

func Index() templ.Component {
	return index()
}

func ErrorPage(msg string, mail string) templ.Component {
	return errorPage(msg, mail)
}

func Bench() templ.Component {
	return bench()
}
