package platform

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Context
	}{
		{"github pr", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main", "GITHUB_SHA": "abc", "GITHUB_REPOSITORY": "o/r"},
			Context{Platform: "github", Event: EventPR, HeadSHA: "abc", BaseRef: "main", Repo: "o/r"}},
		{"github pr target", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_BASE_REF": "dev"},
			Context{Platform: "github", Event: EventPR, BaseRef: "dev"}},
		{"github schedule", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "schedule"},
			Context{Platform: "github", Event: EventSchedule}},
		{"github tag", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag"},
			Context{Platform: "github", Event: EventTag}},
		{"github manual", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"},
			Context{Platform: "github", Event: EventManual}},
		{"github push", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "branch"},
			Context{Platform: "github", Event: EventPush}},
		{"gitlab mr", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "merge_request_event", "CI_MERGE_REQUEST_DIFF_BASE_SHA": "base1", "CI_COMMIT_SHA": "def", "CI_PROJECT_PATH": "g/p", "CI_DEFAULT_BRANCH": "main"},
			Context{Platform: "gitlab", Event: EventPR, HeadSHA: "def", BaseRef: "base1", DefaultBranch: "main", Repo: "g/p"}},
		{"gitlab schedule", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "schedule"},
			Context{Platform: "gitlab", Event: EventSchedule}},
		{"gitlab tag", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v1.0.0"},
			Context{Platform: "gitlab", Event: EventTag}},
		{"gitlab web", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "web"},
			Context{Platform: "gitlab", Event: EventManual}},
		{"gitlab api", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "api"},
			Context{Platform: "gitlab", Event: EventManual}},
		{"gitlab push", map[string]string{"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push"},
			Context{Platform: "gitlab", Event: EventPush}},
		{"bitbucket pr", map[string]string{"BITBUCKET_BUILD_NUMBER": "7", "BITBUCKET_PR_ID": "3", "BITBUCKET_PR_DESTINATION_BRANCH": "main", "BITBUCKET_COMMIT": "ghi", "BITBUCKET_REPO_FULL_NAME": "w/r"},
			Context{Platform: "bitbucket", Event: EventPR, HeadSHA: "ghi", BaseRef: "main", Repo: "w/r"}},
		{"bitbucket tag", map[string]string{"BITBUCKET_BUILD_NUMBER": "7", "BITBUCKET_TAG": "v1.0.0"},
			Context{Platform: "bitbucket", Event: EventTag}},
		{"bitbucket push", map[string]string{"BITBUCKET_BUILD_NUMBER": "7"},
			Context{Platform: "bitbucket", Event: EventPush}},
		{"bitbucket schedule override", map[string]string{"BITBUCKET_BUILD_NUMBER": "7", "SHIPGUARD_EVENT": "schedule"},
			Context{Platform: "bitbucket", Event: EventSchedule}},
		{"local", map[string]string{}, Context{Platform: "local", Event: EventPush}},
		{"local override", map[string]string{"SHIPGUARD_EVENT": "manual"}, Context{Platform: "local", Event: EventManual}},
		{"invalid override ignored", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "schedule", "SHIPGUARD_EVENT": "bogus"},
			Context{Platform: "github", Event: EventSchedule}},
		{"pr override without base keeps empty base", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "SHIPGUARD_EVENT": "pr"},
			Context{Platform: "github", Event: EventPR}},
		{"precedence github over gitlab", map[string]string{"GITHUB_ACTIONS": "true", "GITLAB_CI": "true"},
			Context{Platform: "github", Event: EventPush}},
		{"precedence gitlab over bitbucket", map[string]string{"GITLAB_CI": "true", "BITBUCKET_BUILD_NUMBER": "1"},
			Context{Platform: "gitlab", Event: EventPush}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect(env(tt.env)); got != tt.want {
				t.Errorf("Detect() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDetectNilGetenv(t *testing.T) {
	if got := Detect(nil); got.Platform != "local" || got.Event != EventPush {
		t.Errorf("Detect(nil) = %+v", got)
	}
}
