package hosts

import (
	"math"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/ubuntu_status.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseUbuntuStatusFixture(t *testing.T) {
	s, cpu := parseStatus(fixture(t))
	if s.Partial || s.Hostname != "web-01" || s.OSVersion != "Ubuntu 24.04.1 LTS" || s.Kernel != "6.8.0-45-generic" {
		t.Fatalf("identity %+v", s)
	}
	if s.CPUCores == nil || *s.CPUCores != 4 || s.UptimeSeconds == nil || *s.UptimeSeconds != 123456.78 || len(s.Load) != 3 || s.Load[1] != 0.61 {
		t.Fatalf("CPU fields %+v", s)
	}
	if !cpu.valid || cpu.total != 9700 || cpu.idle != 8100 {
		t.Fatalf("CPU guest counted twice: %+v", cpu)
	}
	if s.Memory == nil || s.Memory.TotalBytes != 8060928*1024 || s.Memory.AvailableBytes != 5048576*1024 || s.Memory.UsedBytes != 3012352*1024 {
		t.Fatalf("memory %+v", s.Memory)
	}
	if s.Swap == nil || s.Swap.UsedBytes != 97148*1024 {
		t.Fatalf("swap %+v", s.Swap)
	}
	if len(s.Disks) != 2 || s.Disks[1].Mountpoint != "/srv/data with spaces" || s.Disks[1].UsedPercent != 90 {
		t.Fatalf("disks %+v", s.Disks)
	}
	if len(s.FailedServices) != 2 || s.FailedServices[0] != "nginx.service" || len(s.TopCPU) != 3 || s.TopCPU[0].CPUPercent != 35.2 {
		t.Fatalf("services/processes %+v %+v", s.FailedServices, s.TopCPU)
	}
}

func TestParseActualAlpineSSHCollection(t *testing.T) {
	data, err := os.ReadFile("testdata/alpine-live.txt")
	if err != nil {
		t.Fatal(err)
	}
	status, sample := parseStatus(string(data))
	if status.OSVersion != "Alpine Linux v3.24" || status.Kernel != "6.10.14-linuxkit" || status.Hostname == "" || status.Memory == nil || status.CPUCores == nil || *status.CPUCores != 14 {
		t.Fatalf("live SSH fixture identity/metrics %+v", status)
	}
	if !sample.valid || sample.total == 0 || status.Memory.TotalBytes != 8024876*1024 || len(status.Disks) != 1 || len(status.TopCPU) != 5 {
		t.Fatalf("live SSH fixture incomplete %+v %+v", status, sample)
	}
	if status.FailedServicesAvailable || !status.Partial {
		t.Fatal("Alpine without systemd incorrectly reported zero failed units as a verified health metric")
	}
	if math.IsNaN(status.Memory.UsedPercent) || math.IsInf(status.Memory.UsedPercent, 0) {
		t.Fatal("nonfinite memory utilization")
	}
}

func TestPartialAndMissingCommands(t *testing.T) {
	s := ParseStatus("__TAILGATE_HOSTNAME__\nhost\n__TAILGATE_MEMORY__\nMemTotal: invalid kB\n__TAILGATE_DISKS__\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 1000 100 900 10% /\n")
	if !s.Partial || s.Hostname != "host" || s.Memory != nil || s.CPUCores != nil || len(s.Disks) != 1 || len(s.TopCPU) != 0 {
		t.Fatalf("partial output %+v", s)
	}
	if len(s.Warnings) == 0 {
		t.Fatal("partial warning absent")
	}
	var output strings.Builder
	for _, section := range sectionNames {
		output.WriteString("__TAILGATE_" + section + "__\n")
	}
	s = ParseStatus(output.String())
	if s.Memory != nil || s.Swap != nil || len(s.Disks) != 0 || len(s.FailedServices) != 0 || s.CPUUsagePercent != nil {
		t.Fatalf("missing probes invented values %+v", s)
	}
}

func TestCPUDeltaAndReboot(t *testing.T) {
	first := parseCPU("cpu 100 10 20 400 5 1 2 3 30 2")
	second := parseCPU("cpu 150 10 30 450 10 1 4 5 35 3")
	usage := cpuUsage(first, second)
	if usage == nil || math.Abs(*usage-(100*64.0/119.0)) > 0.00001 {
		t.Fatalf("wrong utilization %v", usage)
	}
	if cpuUsage(cpuSample{}, second) != nil || cpuUsage(second, first) != nil || cpuUsage(first, first) != nil {
		t.Fatal("reported utilization without a valid increasing second sample")
	}
	if parseCPU("cpu 1 2 nope 4").valid {
		t.Fatal("accepted malformed sample")
	}
}

func TestMemoryFallbackAndZeroSwap(t *testing.T) {
	mem, swap := parseMemory("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 300 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	if mem == nil || mem.UsedPercent != 50 || swap == nil || swap.UsedPercent != 0 {
		t.Fatalf("fallback %+v %+v", mem, swap)
	}
	mem, _ = parseMemory("MemTotal: 1000 kB\n")
	if mem != nil {
		t.Fatal("invented available memory")
	}
}

func TestMalformedAndNonFiniteMetrics(t *testing.T) {
	if len(parseDisks("/dev/a ext4 NaN 1 2 0% /\n/dev/b ext4 10 2 8 Inf% /\n")) != 0 {
		t.Fatal("accepted invalid disks")
	}
	if len(parseProcesses("1 NaN 1 x\n2 1 Inf y\n3 4 5 valid\n")) != 1 {
		t.Fatal("accepted invalid processes")
	}
	if _, ok := finiteNumber("NaN"); ok {
		t.Fatal("NaN accepted")
	}
}

func TestOSReleaseDoesNotEvaluateShell(t *testing.T) {
	values := parseOSRelease("PRETTY_NAME=\"Test \\\"quoted\\\" \\$HOME $(echo unsafe)\"\nNAME='Test OS'\n")
	if values["PRETTY_NAME"] != "Test \"quoted\" $HOME $(echo unsafe)" || values["NAME"] != "Test OS" {
		t.Fatal(values)
	}
}
