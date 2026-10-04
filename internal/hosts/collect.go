package hosts

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CollectionCommand runs each probe independently: an unavailable systemd,
// process utility, or filesystem must not hide the other available metrics.
const CollectionCommand = `printf '__TAILGATE_HOSTNAME__\n'; hostname 2>/dev/null || true
printf '__TAILGATE_OS__\n'; cat /etc/os-release 2>/dev/null || true
printf '__TAILGATE_KERNEL__\n'; uname -r 2>/dev/null || true
printf '__TAILGATE_UPTIME__\n'; cat /proc/uptime 2>/dev/null || true
printf '__TAILGATE_CORES__\n'; getconf _NPROCESSORS_ONLN 2>/dev/null || true
printf '__TAILGATE_LOAD__\n'; cat /proc/loadavg 2>/dev/null || true
printf '__TAILGATE_CPU__\n'; awk '/^cpu / { print; exit }' /proc/stat 2>/dev/null || true
printf '__TAILGATE_MEMORY__\n'; cat /proc/meminfo 2>/dev/null || true
printf '__TAILGATE_DISKS__\n'; df -P -k -T -x tmpfs -x devtmpfs -x overlay -x squashfs -x ramfs 2>/dev/null || true
printf '__TAILGATE_FAILED__\n'; systemctl --failed --no-legend --plain --no-pager 2>/dev/null; tailgate_failed_rc=$?
printf '__TAILGATE_FAILED_AVAILABLE__\n'; if [ "$tailgate_failed_rc" -eq 0 ]; then printf '1\n'; else printf '0\n'; fi
printf '__TAILGATE_TOP_CPU__\n'; ps -eo pid=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -n 5 || true
printf '__TAILGATE_TOP_MEMORY__\n'; ps -eo pid=,pcpu=,pmem=,comm= --sort=-pmem 2>/dev/null | head -n 5 || true
printf '__TAILGATE_END__\n'; true`

type cpuSample struct {
	total, idle uint64
	valid       bool
}

var sectionNames = []string{"HOSTNAME", "OS", "KERNEL", "UPTIME", "CORES", "LOAD", "CPU", "MEMORY", "DISKS", "FAILED", "FAILED_AVAILABLE", "TOP_CPU", "TOP_MEMORY", "END"}

func parseSections(output string) map[string]string {
	sections := map[string]string{}
	name := ""
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		marker := false
		for _, candidate := range sectionNames {
			if line == "__TAILGATE_"+candidate+"__" {
				name = candidate
				sections[name] = ""
				marker = true
				break
			}
		}
		if !marker && name != "" {
			sections[name] += line + "\n"
		}
	}
	return sections
}

// ParseStatus accepts captured output fixtures without depending on SSH.
// CPU usage is deliberately computed by Monitor from two successive samples.
func ParseStatus(output string) Status {
	s, _ := parseStatus(output)
	return s
}

func parseStatus(output string) (Status, cpuSample) {
	sections := parseSections(output)
	s := emptyStatus("")
	for _, name := range sectionNames {
		if name == "FAILED_AVAILABLE" {
			continue
		}
		if _, ok := sections[name]; !ok {
			s.Partial = true
			s.Warnings = append(s.Warnings, "missing "+strings.ToLower(name)+" section")
		}
	}
	s.Hostname = strings.TrimSpace(sections["HOSTNAME"])
	s.Kernel = strings.TrimSpace(sections["KERNEL"])
	os := parseOSRelease(sections["OS"])
	s.OSVersion = os["PRETTY_NAME"]
	if s.OSVersion == "" {
		s.OSVersion = strings.TrimSpace(os["NAME"] + " " + os["VERSION"])
	}
	if fields := strings.Fields(sections["UPTIME"]); len(fields) > 0 {
		if n, ok := finiteNumber(fields[0]); ok && n >= 0 {
			s.UptimeSeconds = &n
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(sections["CORES"])); err == nil && n > 0 {
		s.CPUCores = &n
	}
	if fields := strings.Fields(sections["LOAD"]); len(fields) >= 3 {
		values := []float64{}
		for _, v := range fields[:3] {
			n, ok := finiteNumber(v)
			if !ok || n < 0 {
				values = nil
				break
			}
			values = append(values, n)
		}
		if values != nil {
			s.Load = values
		}
	}
	s.Memory, s.Swap = parseMemory(sections["MEMORY"])
	s.Disks = parseDisks(sections["DISKS"])
	s.FailedServices = parseFailed(sections["FAILED"])
	s.FailedServicesAvailable = strings.TrimSpace(sections["FAILED_AVAILABLE"]) == "1" || len(s.FailedServices) > 0
	if !s.FailedServicesAvailable {
		s.Partial = true
		s.Warnings = append(s.Warnings, "systemd failed-service status is unavailable")
	}
	s.TopCPU = parseProcesses(sections["TOP_CPU"])
	s.TopMemory = parseProcesses(sections["TOP_MEMORY"])
	return s, parseCPU(sections["CPU"])
}

func finiteNumber(value string) (float64, bool) {
	n, err := strconv.ParseFloat(value, 64)
	return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
}

func parseOSRelease(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		} else if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
			var unescaped strings.Builder
			for i := 0; i < len(value); i++ {
				if value[i] == '\\' && i+1 < len(value) && strings.ContainsRune("\\\"$`", rune(value[i+1])) {
					i++
				}
				unescaped.WriteByte(value[i])
			}
			value = unescaped.String()
		}
		values[strings.TrimSpace(key)] = value
	}
	return values
}

func parseCPU(output string) cpuSample {
	fields := strings.Fields(output)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}
	}
	var sample cpuSample
	// guest and guest_nice are already included in user and nice; omit them.
	end := len(fields)
	if end > 9 {
		end = 9
	}
	for i := 1; i < end; i++ {
		n, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil || math.MaxUint64-sample.total < n {
			return cpuSample{}
		}
		sample.total += n
		if i == 4 || i == 5 {
			if math.MaxUint64-sample.idle < n {
				return cpuSample{}
			}
			sample.idle += n
		}
	}
	sample.valid = true
	return sample
}

func cpuUsage(previous, current cpuSample) *float64 {
	if !previous.valid || !current.valid || current.total <= previous.total || current.idle < previous.idle {
		return nil
	}
	total, idle := current.total-previous.total, current.idle-previous.idle
	if idle > total {
		return nil
	}
	usage := 100 * float64(total-idle) / float64(total)
	return &usage
}

func parseMemory(output string) (*Memory, *Swap) {
	values := map[string]uint64{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && strings.EqualFold(fields[1], "kb") {
			if n > math.MaxUint64/1024 {
				continue
			}
			n *= 1024
		}
		values[key] = n
	}
	var mem *Memory
	if total, ok := values["MemTotal"]; ok && total > 0 {
		available, known := values["MemAvailable"]
		if !known {
			// Older kernels lack MemAvailable; use the traditional reclaimable estimate.
			free, freeKnown := values["MemFree"]
			buffers, buffersKnown := values["Buffers"]
			cached, cachedKnown := values["Cached"]
			if freeKnown && buffersKnown && cachedKnown && free <= math.MaxUint64-buffers && free+buffers <= math.MaxUint64-cached {
				available = free + buffers + cached
				known = true
			}
		}
		if known {
			if available > total {
				available = total
			}
			mem = &Memory{TotalBytes: total, AvailableBytes: available, UsedBytes: total - available, UsedPercent: 100 * float64(total-available) / float64(total)}
		}
	}
	var swap *Swap
	if total, ok := values["SwapTotal"]; ok {
		if free, known := values["SwapFree"]; known {
			if free > total {
				free = total
			}
			swap = &Swap{TotalBytes: total, FreeBytes: free, UsedBytes: total - free}
			if total > 0 {
				swap.UsedPercent = 100 * float64(total-free) / float64(total)
			}
		}
	}
	return mem, swap
}

func parseDisks(output string) []Disk {
	disks := []Disk{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] == "Filesystem" {
			continue
		}
		index := 1
		kind := ""
		if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
			index = 2
			kind = fields[1]
		}
		if len(fields) < index+5 {
			continue
		}
		if kind == "tmpfs" || kind == "devtmpfs" || kind == "overlay" || kind == "squashfs" || kind == "ramfs" {
			continue
		}
		total, e1 := strconv.ParseUint(fields[index], 10, 64)
		used, e2 := strconv.ParseUint(fields[index+1], 10, 64)
		available, e3 := strconv.ParseUint(fields[index+2], 10, 64)
		percent, ok := finiteNumber(strings.TrimSuffix(fields[index+3], "%"))
		if e1 != nil || e2 != nil || e3 != nil || !ok || percent < 0 || total > math.MaxUint64/1024 || used > math.MaxUint64/1024 || available > math.MaxUint64/1024 {
			continue
		}
		disks = append(disks, Disk{Filesystem: fields[0], Type: kind, Mountpoint: strings.Join(fields[index+4:], " "), TotalBytes: total * 1024, UsedBytes: used * 1024, AvailableBytes: available * 1024, UsedPercent: percent})
	}
	return disks
}

func parseFailed(output string) []string {
	units := []string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "●" {
			fields = fields[1:]
			if len(fields) == 0 {
				continue
			}
		}
		if len(fields) >= 4 && fields[2] == "failed" {
			units = append(units, fields[0])
		}
	}
	return units
}

func parseProcesses(output string) []Process {
	processes := []Process{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		cpu, cpuOK := finiteNumber(fields[1])
		memory, memoryOK := finiteNumber(fields[2])
		if err != nil || pid <= 0 || !cpuOK || !memoryOK || cpu < 0 || memory < 0 {
			continue
		}
		processes = append(processes, Process{PID: pid, CPUPercent: cpu, MemoryPercent: memory, Command: strings.Join(fields[3:], " ")})
		if len(processes) == 5 {
			break
		}
	}
	return processes
}

func statusSummary(s Status) string {
	return fmt.Sprintf("online=%t hostname=%s os=%s disks=%d failed_services=%d partial=%t", s.Online, s.Hostname, s.OSVersion, len(s.Disks), len(s.FailedServices), s.Partial)
}
