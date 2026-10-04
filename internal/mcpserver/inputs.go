package mcpserver

type listHostsInput struct {
	Tag string `json:"tag,omitempty" jsonschema:"Optional tag used to select configured hosts."`
}

type overviewInput struct {
	Host    string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Refresh bool   `json:"refresh,omitempty" jsonschema:"Collect a fresh host status instead of returning the cached sample."`
}

type runInput struct {
	Host       string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Command    string `json:"command" jsonschema:"Non-interactive Linux shell command that terminates; executed verbatim."`
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"Command timeout in seconds; defaults to the configured timeout. Must be positive and no greater than the configured maximum."`
	Workdir    string `json:"workdir,omitempty" jsonschema:"Optional remote working directory; safely quoted as one shell argument."`
}

type multiInput struct {
	Hosts      []string `json:"hosts,omitempty" jsonschema:"Explicit configured host names. Supply either hosts or tag, not both."`
	Tag        string   `json:"tag,omitempty" jsonschema:"Host tag to select. Supply either tag or hosts, not both."`
	Command    string   `json:"command" jsonschema:"Terminating non-interactive Linux shell command to execute in parallel."`
	TimeoutSec int      `json:"timeout_sec,omitempty" jsonschema:"Per-host timeout in seconds, bounded by the configured maximum."`
}

type readInput struct {
	Host       string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Path       string `json:"path" jsonschema:"Remote text file path; treated as a literal shell argument."`
	OffsetLine int    `json:"offset_line,omitempty" jsonschema:"First line to read, numbered from 1. Defaults to 1."`
	MaxLines   int    `json:"max_lines,omitempty" jsonschema:"Maximum number of lines to return; defaults to 500."`
}

type tailInput struct {
	Host       string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Path       string `json:"path" jsonschema:"Remote log file path; treated as a literal shell argument."`
	Lines      int    `json:"lines,omitempty" jsonschema:"Number of trailing lines to inspect; defaults to 200."`
	Grep       string `json:"grep,omitempty" jsonschema:"Optional regular expression to filter the trailing lines."`
	IgnoreCase bool   `json:"ignore_case,omitempty" jsonschema:"Match the grep expression without case sensitivity."`
}

type journalInput struct {
	Host     string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Unit     string `json:"unit,omitempty" jsonschema:"Optional systemd unit name, for example nginx.service."`
	Since    string `json:"since,omitempty" jsonschema:"Start time understood by journalctl, for example 2026-10-04 08:00:00."`
	Until    string `json:"until,omitempty" jsonschema:"End time understood by journalctl."`
	Priority string `json:"priority,omitempty" jsonschema:"Journal priority accepted by journalctl, for example err or 0..3."`
	Lines    int    `json:"lines,omitempty" jsonschema:"Maximum journal entries to return; defaults to 200."`
	Grep     string `json:"grep,omitempty" jsonschema:"Optional regular expression used by journalctl to filter messages."`
}

type serviceInput struct {
	Host string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Unit string `json:"unit" jsonschema:"Systemd unit name whose status and recent journal entries should be returned."`
}

type dirInput struct {
	Host string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Path string `json:"path" jsonschema:"Remote directory path; treated as a literal shell argument."`
	All  bool   `json:"all,omitempty" jsonschema:"Include entries whose names begin with a dot."`
}

type searchInput struct {
	Host        string `json:"host" jsonschema:"Configured host name returned by list_hosts."`
	Path        string `json:"path" jsonschema:"Remote directory below which to search."`
	Pattern     string `json:"pattern" jsonschema:"Filename glob, for example *.log; safely quoted as one argument."`
	ContentGrep string `json:"content_grep,omitempty" jsonschema:"Optional regular expression to match within candidate files."`
	MaxResults  int    `json:"max_results,omitempty" jsonschema:"Maximum number of matching files to return; defaults to 100."`
}
