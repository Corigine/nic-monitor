package nicmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corigine/nic-monitor/pkg/nfp"
	"github.com/k8snetworkplumbingwg/sriovnet"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	internalapi "k8s.io/cri-api/pkg/apis"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

var podRwlock sync.RWMutex
var podToVfIndexMap map[string]map[string]interface{} = make(map[string]map[string]interface{})
var switchIdtoPci map[string]interface{} = make(map[string]interface{})
var defaultTimeout = 2 * time.Second
var defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///var/run/dockershim.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}
var pciDeviceRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.\d{1}`)

// Regex that matches on VF representor port name
var vfPortRepRegex = regexp.MustCompile(`^(?:c\d+)?pf(\d+)vf(\d+)$`)

func parseIndexFromPhysPortName(portName string, regex *regexp.Regexp) (pfRepIndex, vfRepIndex int, err error) {
	pfRepIndex = -1
	vfRepIndex = -1

	matches := regex.FindStringSubmatch(portName)
	//nolint:gomnd
	if len(matches) != 3 {
		err = fmt.Errorf("failed to parse portName %s", portName)
	} else {
		pfRepIndex, err = strconv.Atoi(matches[1])
		if err == nil {
			vfRepIndex, err = strconv.Atoi(matches[2])
		}
	}
	return pfRepIndex, vfRepIndex, err
}

func parsePortName(physPortName string) (pfRepIndex, vfRepIndex int, err error) {
	// old kernel syntax of phys_port_name is vf index
	physPortName = strings.TrimSpace(physPortName)
	physPortNameInt, err := strconv.Atoi(physPortName)
	if err == nil {
		vfRepIndex = physPortNameInt
	} else {
		pfRepIndex, vfRepIndex, err = parseIndexFromPhysPortName(physPortName, vfPortRepRegex)
	}
	return pfRepIndex, vfRepIndex, err
}

func getSriovVfInfo(sandboxId string, info map[string]interface{}) bool {
	var ifname string
	if os.Getenv("CNI_VENDOR") == "FABRIC" {
		ifname = strings.Replace(sandboxId, ":", "", -1)
	} else {
		ifname = fmt.Sprintf("%s_h", sandboxId[0:12])
	}
	devicePortNameFile := filepath.Join(nfp.NetSysDir, ifname, nfp.NetdevPhysPortName)
	physPortName, err := os.ReadFile(devicePortNameFile)
	if err != nil {
		return false
	}
	info["rep"] = ifname
	_, vfindex, err := parsePortName(strings.TrimSpace(string(physPortName)))
	if err != nil {
		klog.Errorf("Parese phy port name error for %s", ifname)
		return false
	}
	info["vf"] = vfindex
	swIDFile := filepath.Join(nfp.NetSysDir, ifname, "phys_switch_id")
	physSwitchID, err := os.ReadFile(swIDFile)
	if err != nil {
		klog.Errorf("Can not get the switchid for %s", ifname)
		return false
	}

	pci, ok := switchIdtoPci[strings.TrimSpace(string(physSwitchID))]
	if !ok {
		klog.Errorf("Can not get pci for %s", ifname)
		return false
	}
	info["pci"] = pci
	return true

}

func getPodAndSriovVf(containerId string) (podName string, info map[string]interface{}) {
	var err error
	var rs internalapi.RuntimeService

	for _, endPoint := range defaultRuntimeEndpoints {
		rs, err = remote.NewRemoteRuntimeService(endPoint, defaultTimeout, nil)
		if err != nil {
			klog.Errorf("Connect using endpoint %q error:%v", endPoint, err)
			continue
		}
		klog.Info("Connected successfully using endpoint:", endPoint)
		break
	}
	if rs == nil {
		klog.Info("Can not connect the the docker runtime service")
		return
	}

	rep, err := rs.ContainerStatus(context.TODO(), containerId, true)
	if err != nil {
		klog.Errorf("Can not get container %s from cri runtime:%v", containerId, err)
		return
	}

	result := make(map[string]interface{})
	if json.Unmarshal([]byte(rep.Info["info"]), &result) != nil {
		klog.Errorf("Can not get info for %s", containerId)
		return
	}

	sandboxId, ok := result["sandboxID"].(string)
	if !ok {
		klog.Errorf("Can not get sandboxID for %s", containerId)
		return
	}

	info = make(map[string]interface{})
	if getSriovVfInfo(sandboxId, info) == true {
		info["namespace"] = rep.Status.Labels[types.KubernetesPodNamespaceLabel]
		podName := rep.Status.Labels[types.KubernetesPodNameLabel]
		return podName, info
	}
	return
}

func processPodUpdate(old, obj interface{}) {
	defer utilruntime.HandleCrash()

	if obj.(*v1.Pod).Status.Phase != v1.PodRunning ||
		old.(*v1.Pod).Status.Phase == v1.PodRunning {
		return
	}
	podRwlock.Lock()
	defer podRwlock.Unlock()
	if os.Getenv("CNI_VENDOR") == "FABRIC" {
		ifname, ok := obj.(*v1.Pod).Annotations["kubernetes.customized/fabric-mac"]
		if !ok {
			klog.Infof("Process pod %s add error: no kubernetes.customized/fabric-mac label", obj.(*v1.Pod).Name)
			return
		}
		info := make(map[string]interface{})
		if getSriovVfInfo(ifname, info) == true {
			info["namespace"] = obj.(*v1.Pod).Namespace
			podToVfIndexMap[obj.(*v1.Pod).Name] = info
			klog.Infof("Process pod %s add %v", obj.(*v1.Pod).Name, info)
		}
	} else {
		for _, cs := range obj.(*v1.Pod).Status.ContainerStatuses {
			podname, info := getPodAndSriovVf(strings.Split(cs.ContainerID, "//")[1])
			if podname != "" {
				podToVfIndexMap[podname] = info
				klog.Infof("Process pod %s add %v", podname, info)
			}
		}
	}
}

func processPodAdd(obj interface{}) {
	defer utilruntime.HandleCrash()

	if obj.(*v1.Pod).Status.Phase != v1.PodRunning {
		return
	}
	podRwlock.Lock()
	defer podRwlock.Unlock()
	if os.Getenv("CNI_VENDOR") == "FABRIC" {
		ifname, ok := obj.(*v1.Pod).Annotations["kubernetes.customized/fabric-mac"]
		if !ok {
			klog.Infof("Process pod %s add error: no kubernetes.customized/fabric-mac label", obj.(*v1.Pod).Name)
			return
		}
		info := make(map[string]interface{})
		if getSriovVfInfo(ifname, info) == true {
			info["namespace"] = obj.(*v1.Pod).Namespace
			podToVfIndexMap[obj.(*v1.Pod).Name] = info
			klog.Infof("Process pod %s add %v", obj.(*v1.Pod).Name, info)
		}
	} else {
		for _, cs := range obj.(*v1.Pod).Status.ContainerStatuses {
			podname, info := getPodAndSriovVf(strings.Split(cs.ContainerID, "//")[1])
			if podname != "" {
				podToVfIndexMap[podname] = info
				klog.Infof("Process pod %s add %v", podname, info)
			}
		}
	}
}

func processPodDelete(obj interface{}) {
	podRwlock.Lock()
	defer podRwlock.Unlock()

	podName := obj.(*v1.Pod).Name
	delete(podToVfIndexMap, podName)
	klog.Infof("Process pod %s delete", podName)
}

func startUpdatePodInfoFromK8s(client *kubernetes.Clientset, stopCh chan struct{}) {
	labelOptions := informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", os.Getenv("NODE_NAME"))
	})

	sharedInformers := informers.NewSharedInformerFactoryWithOptions(client, 0, labelOptions)
	informer := sharedInformers.Core().V1().Pods().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    processPodAdd,
		UpdateFunc: processPodUpdate,
		DeleteFunc: processPodDelete,
	})
	informer.Run(stopCh)
}

func init() {
	pciDevice := nfp.GetCorigineNicDevice()
	for _, pci := range pciDevice {
		netDevs, _ := sriovnet.GetNetDevicesFromPci(pci)
		for _, netDev := range netDevs {
			swIDFile := filepath.Join(nfp.NetSysDir, netDev, "phys_switch_id")
			physSwitchID, err := os.ReadFile(swIDFile)
			if err != nil || len(physSwitchID) == 0 {
				continue
			}
			switchIdtoPci[strings.TrimSpace(string(physSwitchID))] = pci
			break
		}
	}
}
