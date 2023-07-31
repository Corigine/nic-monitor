package util

import (
	"os"
	"path/filepath"
	"strings"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

func GetBondSlave(ifname string) []string {
	defer utilruntime.HandleCrash()

	devs := make([]string, 0)
	bondPath := filepath.Join("/proc/net/bonding/", ifname)
	bondInfo, err := os.ReadFile(bondPath)
	if err != nil {
		return nil
	}
	lineArr := strings.Split(string(bondInfo), "\n")
	for _, line := range lineArr {
		if strings.Contains(line, "Slave Interface") {
			devs = append(devs, strings.TrimSpace(strings.Split(line, ":")[1]))
		}
	}
	return devs
}
