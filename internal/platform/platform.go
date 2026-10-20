// Package platform detects the CI platform and the triggering event.
package platform

import "strings"

// Event is the kind of CI trigger: pr, push, tag, schedule or manual.
type Event string

const (
	EventPR       Event = "pr"
	EventPush     Event = "push"
	EventTag      Event = "tag"
	EventSchedule Event = "schedule"
	EventManual   Event = "manual"
)

// BitbucketPipeProxy is the Pipelines auth proxy as seen from a pipe, which
// runs in its own container; steps reach it at localhost:29418.
const BitbucketPipeProxy = "http://host.docker.internal:29418"

// BitbucketPipe reports whether shipguard runs as a Bitbucket pipe.
func BitbucketPipe(getenv func(string) string) bool {
	return getenv("BITBUCKET_BUILD_NUMBER") != "" && getenv("BITBUCKET_PIPE_STORAGE_DIR") != ""
}

// BitbucketPipeGitConfig returns the git settings a Bitbucket pipe needs to
// fetch from origin. The clone's .git/config routes origin through
// localhost:29418, which a pipe cannot reach, so the proxy is overridden for
// that origin. It returns nil outside a pipe or for an unexpected origin.
func BitbucketPipeGitConfig(getenv func(string) string) []string {
	if !BitbucketPipe(getenv) {
		return nil
	}
	origin := getenv("BITBUCKET_GIT_HTTP_ORIGIN")
	if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
		return nil
	}
	if strings.ContainsAny(origin, "= \t\r\n") {
		return nil
	}
	return []string{"http." + origin + ".proxy=" + BitbucketPipeProxy + "/"}
}

// Context describes where and why shipguard is running.
type Context struct {
	Platform      string `json:"platform"` // github | gitlab | bitbucket | local
	Event         Event  `json:"event"`
	HeadSHA       string `json:"head_sha"`
	BaseRef       string `json:"base_ref"` // only for pr: branch name or SHA
	DefaultBranch string `json:"default_branch"`
	Repo          string `json:"repo"`
}

// Detect resolves the platform and event from environment variables.
// SHIPGUARD_EVENT overrides the detected event when it is a valid event.
func Detect(getenv func(string) string) Context {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	c := Context{Platform: "local", Event: EventPush}
	switch {
	case getenv("GITHUB_ACTIONS") == "true":
		c.Platform = "github"
		c.HeadSHA = getenv("GITHUB_SHA")
		c.Repo = getenv("GITHUB_REPOSITORY")
		switch getenv("GITHUB_EVENT_NAME") {
		case "pull_request", "pull_request_target":
			c.Event, c.BaseRef = EventPR, getenv("GITHUB_BASE_REF")
		case "schedule":
			c.Event = EventSchedule
		default:
			switch {
			case getenv("GITHUB_REF_TYPE") == "tag":
				c.Event = EventTag
			case getenv("GITHUB_EVENT_NAME") == "workflow_dispatch":
				c.Event = EventManual
			}
		}
	case getenv("GITLAB_CI") == "true":
		c.Platform = "gitlab"
		c.HeadSHA = getenv("CI_COMMIT_SHA")
		c.Repo = getenv("CI_PROJECT_PATH")
		c.DefaultBranch = getenv("CI_DEFAULT_BRANCH")
		switch src := getenv("CI_PIPELINE_SOURCE"); {
		case src == "merge_request_event":
			c.Event, c.BaseRef = EventPR, getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
		case src == "schedule":
			c.Event = EventSchedule
		case getenv("CI_COMMIT_TAG") != "":
			c.Event = EventTag
		case src == "web" || src == "api":
			c.Event = EventManual
		}
	case getenv("BITBUCKET_BUILD_NUMBER") != "":
		c.Platform = "bitbucket"
		c.HeadSHA = getenv("BITBUCKET_COMMIT")
		c.Repo = getenv("BITBUCKET_REPO_FULL_NAME")
		switch {
		case getenv("BITBUCKET_PR_ID") != "":
			c.Event, c.BaseRef = EventPR, getenv("BITBUCKET_PR_DESTINATION_BRANCH")
		case getenv("BITBUCKET_TAG") != "":
			c.Event = EventTag
		}
	}
	switch ev := Event(getenv("SHIPGUARD_EVENT")); ev {
	case EventPR, EventPush, EventTag, EventSchedule, EventManual:
		c.Event = ev
	}
	return c
}
