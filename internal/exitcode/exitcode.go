// Package exitcode defines shipguard's process exit codes.
package exitcode

import "strconv"

// Process exit codes.
const (
	// Pass means the scan passed, or ran in audit mode.
	Pass = 0
	// Fail means a policy failure.
	Fail = 1
	// Error means a tool or configuration error.
	Error = 2
)

// Err carries an exit code together with the underlying error.
type Err struct {
	Code int
	Err  error
}

func (e *Err) Error() string {
	if e.Err == nil {
		return "exit status " + strconv.Itoa(e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *Err) Unwrap() error { return e.Err }
