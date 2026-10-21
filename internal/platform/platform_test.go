package platform

import (
	"encoding/json"
	"testing"
)

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
		{"github dispatch on tag", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_TYPE": "tag"},
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
		{"github actions false is not github", map[string]string{"GITHUB_ACTIONS": "false", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main", "GITHUB_SHA": "abc"},
			Context{Platform: "local", Event: EventPush}},
		{"github actions false falls through to gitlab", map[string]string{"GITHUB_ACTIONS": "false", "GITLAB_CI": "true", "CI_COMMIT_SHA": "def"},
			Context{Platform: "gitlab", Event: EventPush, HeadSHA: "def"}},
		{"gitlab ci false is not gitlab", map[string]string{"GITLAB_CI": "false", "CI_PIPELINE_SOURCE": "merge_request_event"},
			Context{Platform: "local", Event: EventPush}},
		{"bitbucket pr wins over tag", map[string]string{"BITBUCKET_BUILD_NUMBER": "7", "BITBUCKET_PR_ID": "3", "BITBUCKET_PR_DESTINATION_BRANCH": "main", "BITBUCKET_TAG": "v1.0.0"},
			Context{Platform: "bitbucket", Event: EventPR, BaseRef: "main"}},
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

func TestContextJSONKeys(t *testing.T) {
	b, err := json.Marshal(Context{Platform: "github", Event: EventPR, HeadSHA: "a", BaseRef: "b", DefaultBranch: "c", Repo: "d"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"platform":"github","event":"pr","head_sha":"a","base_ref":"b","default_branch":"c","repo":"d"}`
	if string(b) != want {
		t.Errorf("json = %s, want %s", b, want)
	}
}

func TestBitbucketPipeGitConfig(t *testing.T) {
	pipe := map[string]string{"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_PIPE_STORAGE_DIR": "/x"}
	with := func(origin string) map[string]string {
		m := map[string]string{"BITBUCKET_GIT_HTTP_ORIGIN": origin}
		for k, v := range pipe {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"pipe", with("http://bitbucket.org/ws/repo"), []string{"http.http://bitbucket.org/ws/repo.proxy=http://host.docker.internal:29418/"}},
		{"step image", map[string]string{"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_GIT_HTTP_ORIGIN": "http://bitbucket.org/ws/repo"}, nil},
		{"not bitbucket", map[string]string{"BITBUCKET_PIPE_STORAGE_DIR": "/x", "BITBUCKET_GIT_HTTP_ORIGIN": "http://bitbucket.org/ws/repo"}, nil},
		{"no origin", pipe, nil},
		{"not http", with("ssh://git@bitbucket.org/ws/repo"), nil},
		{"equals sign", with("http://bitbucket.org/ws/repo.proxy=http://evil:1/?a"), nil},
		{"whitespace", with("http://bitbucket.org/ws/repo\nx"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BitbucketPipeGitConfig(env(tc.env))
			if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
