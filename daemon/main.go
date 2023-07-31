package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/corigine/nic-monitor/pkg/nicmonitor"
	"github.com/corigine/nic-monitor/pkg/util"
	"github.com/corigine/nic-monitor/versions"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog"
)

func main() {
	var addr string
	defer klog.Flush()

	klog.Infof(versions.String())
	config, err := nicmonitor.ParseFlags()
	if err != nil {
		util.LogFatalAndExit(err, "failed to parse config")
	}
	exporter := nicmonitor.NewExporter(config)
	exporter.StartNicMetrics()
	monitor := nicmonitor.NewNicMonitor(config)
	monitor.StartNicMonitor()

	http.Handle(config.MetricsPath, promhttp.Handler())

	podIpsEnv := os.Getenv("POD_IPS")
	podIps := strings.Split(podIpsEnv, ",")
	if len(podIps) == 1 {
		ip := net.ParseIP(podIps[0])
		if ip.To4() != nil {
			addr = fmt.Sprintf("[%s]:%d", podIps[0], config.ListenPort)
		} else {
			addr = fmt.Sprintf("%s:%d", podIps[0], config.ListenPort)
		}
	}

	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 3 * time.Second,
	}
	klog.Infoln("Listening on", addr)
	util.LogFatalAndExit(server.ListenAndServe(), "failed to listen and server on %s", addr)
}
