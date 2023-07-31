package nicmonitor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corigine/nic-monitor/pkg/nfp"
	"github.com/k8snetworkplumbingwg/sriovnet"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

type Exporter struct {
	pollInterval int
	stasInterval int
	Hostname     string
	pciDevice    []string
	devs         []string
}

const (
	sysFlowerDebugDir = "/sys/kernel/debug/nfp_net"
)

var registerNicMetricsOnce sync.Once

// NewExporter returns an initialized Exporter.
func NewExporter(cfg *Configuration) *Exporter {
	e := Exporter{}
	e.pciDevice = nfp.GetCorigineNicDevice()
	e.Hostname = os.Getenv("NODE_NAME")
	e.pollInterval = cfg.PullInterval
	e.stasInterval = cfg.StasInterval
	return &e
}

func (e *Exporter) initCoriginePhyDevs() {
	e.devs = []string{}
	for _, pci := range e.pciDevice {
		devs, err := sriovnet.GetNetDevicesFromPci(pci)
		if err != nil {
			klog.Errorf("Get the device %s devs error", pci)
			continue
		}
		for _, dev := range devs {
			swIDFile := filepath.Join(nfp.NetSysDir, dev, "phys_switch_id")
			_, err := os.ReadFile(swIDFile)
			if err != nil {
				continue
			}
			e.devs = append(e.devs, dev)
		}
	}
}

// StartNicMetrics register and start to update nic metrics

func (e *Exporter) StartNicMetrics() {
	stopCh := make(chan struct{})

	registerNicMetricsOnce.Do(func() {
		e.initCoriginePhyDevs()
		registerNicMetrics()
		go startUpdatePodInfoFromK8s(KubeClient, stopCh)
		go wait.Until(e.exportNicStatisticGauge, time.Duration(e.stasInterval)*time.Second, stopCh)
		go wait.Until(e.nicMetricsUpdate, time.Duration(e.pollInterval)*time.Second, stopCh)
	})
}

func (e *Exporter) nicMetricsUpdate() {
	e.exportNicGauge()
	e.exportNicFlowNumGauge()
	e.exportNicStatusGauge()
}

func (e *Exporter) exportNicGauge() {
	metricNicTemperature.Reset()
	metricNicLatancy.Reset()
	for index, pci := range e.pciDevice {
		args := fmt.Sprintf("-n %d", index)
		cmd := exec.Command("/opt/netronome/bin/nfp-temp", args)
		out, err := cmd.CombinedOutput()
		if err != nil {
			klog.Errorf("failed to exec command nfp-temp %v", err)
		}
		outStr := strings.Split(string(out), ":")
		if len(outStr) != 2 {
			continue
		}
		temp, err := strconv.ParseFloat(strings.TrimSpace(outStr[1]), 64)
		if err == nil {
			metricNicTemperature.WithLabelValues(e.Hostname, pci).Set(temp)
		} else {
			klog.Errorf("failed to get nic[%s] temperature: %v", pci, err)
		}

		args = fmt.Sprintf("-n %d", index)
		cmd = exec.Command("/opt/netronome/bin/nfp-rtsym", args, "PKT_LAT_DATA_GLOB")
		out, err = cmd.CombinedOutput()
		if err != nil {
			klog.Errorf("failed to exec command nfp-rtsym %v", err)
		}
		outStr = strings.Split(string(out), ":")
		if len(outStr) != 2 {
			continue
		}
		latancy, err := strconv.ParseUint(strings.TrimSpace(outStr[1])[2:], 16, 32)
		if err == nil {
			if (latancy & 0xFF000000) == 0 {
				//klog.Errorf("The nic latancy value is invailid.")
				continue
			}
			latancy = (latancy&0xFFFFFF)*16/1000 + nfp.NFP_PCIE_LAT
			metricNicLatancy.WithLabelValues(e.Hostname, pci).Set(float64(latancy))
		} else {
			klog.Errorf("failed to get nic[%s] latancy: %v", pci, err)
		}
	}
}

func (e *Exporter) exportNicFlowNumGauge() {
	defer utilruntime.HandleCrash()

	metricNicFlowNum.Reset()
	podRwlock.RLock()
	for podName, podInfo := range podToVfIndexMap {
		for _, vfInfo := range podInfo.vfReps {
			pci := vfInfo.pci
			podNs := podInfo.namespace
			vfIndex := vfInfo.vfindex
			flowNumFile := filepath.Join(sysFlowerDebugDir, pci, fmt.Sprintf("vf%d", vfIndex), "flow_num")
			flowNumByte, err := os.ReadFile(flowNumFile)
			if err != nil {
				klog.Errorf("Read the flow num error for %s vf%d", pci, vfIndex)
				continue
			}
			flowNum, err := strconv.Atoi(strings.TrimSpace(string(flowNumByte)))
			if err != nil {
				klog.Errorf("The flow num %s format error", string(flowNumByte))
				continue
			}
			metricNicFlowNum.WithLabelValues(podNs, podName, pci).Set(float64(flowNum))
		}
	}
	podRwlock.RUnlock()
	for _, pci := range e.pciDevice {
		flowNumFile := filepath.Join(sysFlowerDebugDir, pci, "total_flow_num")
		flowNumBuf, err := os.ReadFile(flowNumFile)
		if err != nil {
			klog.Errorf("Read the flow num error for %s", pci)
			continue
		}
		flowNum, err := strconv.Atoi(strings.TrimSpace(string(flowNumBuf)))
		if err != nil {
			klog.Errorf("The flow num format error:%v", err)
			continue
		}
		metricNicFlowNum.WithLabelValues(e.Hostname, pci, pci).Set(float64(flowNum))
	}
}

func getAllDevStatistics() (stats map[string]interface{}, err error) {
	statsBuf, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	stats = make(map[string]interface{})
	lineArr := strings.Split(string(statsBuf), "\n")
	for i := 2; i < len(lineArr); i++ {
		devArr := strings.Split(lineArr[i], ":")
		if len(devArr) != 2 {
			continue
		}
		devName := strings.TrimSpace(devArr[0])
		stats[devName] = make(map[string]string)
		dArr := strings.Fields(strings.TrimSpace(devArr[1]))
		if len(dArr) == 16 {
			stats[devName].(map[string]string)["rxByte"] = dArr[0]
			stats[devName].(map[string]string)["rxPkt"] = dArr[1]
			stats[devName].(map[string]string)["rxDrop"] = dArr[3]
			stats[devName].(map[string]string)["txByte"] = dArr[8]
			stats[devName].(map[string]string)["txPkt"] = dArr[9]
			stats[devName].(map[string]string)["txDrop"] = dArr[11]
		} else {
			err = fmt.Errorf("Parse %s statstic error.", devName)
			return
		}
	}
	return
}

func (e *Exporter) exportDevStatisticGauge(podNs string,
	podName string,
	dev string,
	stats map[string]interface{},
	pod bool) {

	var tempBuf string
	if pod {
		tempBuf = stats[dev].(map[string]string)["txByte"]
	} else {
		tempBuf = stats[dev].(map[string]string)["rxByte"]
	}
	rxByte, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicRxByte.WithLabelValues(podNs, podName).Set(float64(rxByte))
	} else {
		klog.Errorf("Parse %s statistic rxbyte error.", dev)
	}
	if pod {
		tempBuf = stats[dev].(map[string]string)["txPkt"]
	} else {
		tempBuf = stats[dev].(map[string]string)["rxPkt"]
	}
	rxPkt, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicRxPkt.WithLabelValues(podNs, podName).Set(float64(rxPkt))
	} else {
		klog.Errorf("Parse %s statistic rxPkt error.", dev)
	}
	if pod {
		tempBuf = stats[dev].(map[string]string)["txDrop"]
	} else {
		tempBuf = stats[dev].(map[string]string)["rxDrop"]
	}
	rxDrop, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicRxDropPkt.WithLabelValues(podNs, podName).Set(float64(rxDrop))
	} else {
		klog.Errorf("Parse %s statistic rxDrop error.", dev)
	}
	if pod {
		tempBuf = stats[dev].(map[string]string)["rxByte"]
	} else {
		tempBuf = stats[dev].(map[string]string)["txByte"]
	}
	txByte, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicTxByte.WithLabelValues(podNs, podName).Set(float64(txByte))
	} else {
		klog.Errorf("Parse %s statistic txbyte error.", dev)
	}
	if pod {
		tempBuf = stats[dev].(map[string]string)["rxPkt"]
	} else {
		tempBuf = stats[dev].(map[string]string)["txPkt"]
	}
	txPkt, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicTxPkt.WithLabelValues(podNs, podName).Set(float64(txPkt))
	} else {
		klog.Errorf("Parse %s statistic txPkt error.", dev)
	}
	if pod {
		tempBuf = stats[dev].(map[string]string)["rxDrop"]
	} else {
		tempBuf = stats[dev].(map[string]string)["txDrop"]
	}
	txDrop, err := strconv.ParseInt(tempBuf, 10, 0)
	if err == nil {
		metricNicTxDropPkt.WithLabelValues(podNs, podName).Set(float64(txDrop))
	} else {
		klog.Errorf("Parse %s statistic txDrop error.", dev)
	}
}

func (e *Exporter) exportNicStatisticGauge() {
	defer utilruntime.HandleCrash()

	metricNicRxByte.Reset()
	stats, err := getAllDevStatistics()
	if err != nil {
		klog.Errorf("Read the dev statistic error %v", err)
		return
	}

	podRwlock.RLock()
	for podName, podInfo := range podToVfIndexMap {
		podNs := podInfo.namespace
		dev := podInfo.ifName
		e.exportDevStatisticGauge(podNs, podName, dev, stats, true)
	}
	podRwlock.RUnlock()

	for _, dev := range e.devs {
		e.exportDevStatisticGauge(e.Hostname, dev, dev, stats, false)
	}
}

func (e *Exporter) exportNicStatusGauge() {
	metricNicStatus.Reset()
	for pci, state := range nicState {
		if state {
			metricNicStatus.WithLabelValues(e.Hostname, pci).Set(float64(1))
		} else {
			metricNicStatus.WithLabelValues(e.Hostname, pci).Set(float64(0))
		}
	}
}
