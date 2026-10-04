// Package hosts collects and caches Linux host status through one SSH command.
package hosts

import "time"

type Status struct {
	Host                    string     `json:"host"`
	Online                  bool       `json:"online"`
	SSHLatencyMS            int64      `json:"ssh_latency_ms"`
	CollectedAt             time.Time  `json:"collected_at"`
	LastSuccess             *time.Time `json:"last_success"`
	LastError               string     `json:"last_error"`
	Hostname                string     `json:"hostname"`
	OSVersion               string     `json:"os_version"`
	Kernel                  string     `json:"kernel"`
	UptimeSeconds           *float64   `json:"uptime_seconds"`
	CPUCores                *int       `json:"cpu_cores"`
	Load                    []float64  `json:"load"`
	CPUUsagePercent         *float64   `json:"cpu_usage_percent"`
	Memory                  *Memory    `json:"memory"`
	Swap                    *Swap      `json:"swap"`
	Disks                   []Disk     `json:"disks"`
	FailedServices          []string   `json:"failed_services"`
	FailedServicesAvailable bool       `json:"failed_services_available"`
	TopCPU                  []Process  `json:"top_cpu"`
	TopMemory               []Process  `json:"top_memory"`
	Partial                 bool       `json:"partial"`
	Warnings                []string   `json:"warnings"`
}

type Memory struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type Swap struct {
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

type Disk struct {
	Filesystem     string  `json:"filesystem"`
	Type           string  `json:"type"`
	Mountpoint     string  `json:"mountpoint"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type Process struct {
	PID           int     `json:"pid"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	Command       string  `json:"command"`
}

func emptyStatus(host string) Status {
	return Status{Host: host, Load: []float64{}, Disks: []Disk{}, FailedServices: []string{}, TopCPU: []Process{}, TopMemory: []Process{}, Warnings: []string{}}
}

func cloneStatus(s Status) Status {
	s.Load = append([]float64{}, s.Load...)
	s.Disks = append([]Disk{}, s.Disks...)
	s.FailedServices = append([]string{}, s.FailedServices...)
	s.TopCPU = append([]Process{}, s.TopCPU...)
	s.TopMemory = append([]Process{}, s.TopMemory...)
	s.Warnings = append([]string{}, s.Warnings...)
	if s.LastSuccess != nil {
		value := *s.LastSuccess
		s.LastSuccess = &value
	}
	if s.UptimeSeconds != nil {
		value := *s.UptimeSeconds
		s.UptimeSeconds = &value
	}
	if s.CPUCores != nil {
		value := *s.CPUCores
		s.CPUCores = &value
	}
	if s.CPUUsagePercent != nil {
		value := *s.CPUUsagePercent
		s.CPUUsagePercent = &value
	}
	if s.Memory != nil {
		value := *s.Memory
		s.Memory = &value
	}
	if s.Swap != nil {
		value := *s.Swap
		s.Swap = &value
	}
	return s
}
