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
	"github.com/corigine/nic-monitor/pkg/util"
	"github.com/k8snetworkplumbingwg/sriovnet"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	internalapi "k8s.io/cri-api/pkg/apis"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

type vfRepInfo struct {
	name    string
	vfindex int
	pci     string
}

type podInfo struct {
	namespace string
	vfReps    []vfRepInfo
	ifName    string
	nsPath    string
}

var podRwlock sync.RWMutex
var podToVfIndexMap map[string]podInfo = make(map[string]podInfo)
var switchIdtoPci map[string]string = make(map[string]string)
var defaultTimeout = 2 * time.Second
var defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///var/run/dockershim.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}

//var pciDeviceRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.\d{1}`)

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

func getSriovRepInfo(ifname string) *vfRepInfo {
	var rep vfRepInfo

	devicePortNameFile := filepath.Join(nfp.NetSysDir, ifname, nfp.NetdevPhysPortName)
	physPortName, err := os.ReadFile(devicePortNameFile)
	if err != nil {
		return nil
	}
	rep.name = ifname
	_, vfindex, err := parsePortName(strings.TrimSpace(string(physPortName)))
	if err != nil {
		klog.Errorf("Parese phy port name error for %s", ifname)
		return nil
	}
	rep.vfindex = vfindex
	swIDFile := filepath.Join(nfp.NetSysDir, ifname, "phys_switch_id")
	physSwitchID, err := os.ReadFile(swIDFile)
	if err != nil {
		klog.Errorf("Can not get the switchid for %s", ifname)
		return nil
	}

	pci, ok := switchIdtoPci[strings.TrimSpace(string(physSwitchID))]
	if !ok {
		klog.Errorf("Can not get pci for %s", ifname)
		return nil
	}
	rep.pci = pci
	return &rep
}

func getSriovInfo(sandboxId string, info *podInfo) bool {
	var ifname string
	if os.Getenv("CNI_VENDOR") == "FABRIC" {
		ifname = strings.Replace(sandboxId, ":", "", -1)
	} else {
		ifname = fmt.Sprintf("%s_h", sandboxId[0:12])
	}
	info.ifName = ifname
	devlink, err := netlink.LinkByName(ifname)
	if err != nil {
		klog.Errorf("Get dev %s netlink info error:%v", ifname, err)
		return false
	}

	if devlink.Type() == "bond" {
		slaveDevs := util.GetBondSlave(ifname)
		for _, slave := range slaveDevs {
			rep := getSriovRepInfo(slave)
			if rep != nil {
				info.vfReps = append(info.vfReps, *rep)
			}
		}
	} else {
		rep := getSriovRepInfo(ifname)
		if rep != nil {
			info.vfReps = append(info.vfReps, *rep)
		}
	}

	if len(info.vfReps) != 0 {
		return true
	}
	return false
}

func getPodInfo(containerId string) (map[string]interface{}, error) {
	var rs internalapi.RuntimeService
	var err error

	for _, endPoint := range defaultRuntimeEndpoints {
		rs, err = remote.NewRemoteRuntimeService(endPoint, defaultTimeout, nil)
		if err != nil {
			klog.Errorf("Connect using endpoint %q error:%v", endPoint, err)
			continue
		}
		break
	}
	if rs == nil {
		return nil, fmt.Errorf("Can not connect the the docker runtime service")
	}

	rep, err := rs.ContainerStatus(context.TODO(), containerId, true)
	if err != nil {
		return nil, fmt.Errorf("Can not get container %s from cri runtime:%v", containerId, err)
	}

	result := make(map[string]interface{})
	if json.Unmarshal([]byte(rep.Info["info"]), &result) != nil {
		return nil, fmt.Errorf("Can not get info for %s", containerId)
	}
	return result, nil
}

func getPodSandboxId(info map[string]interface{}) (string, error) {
	sandboxId, ok := info["sandboxID"].(string)
	if !ok {
		return "", fmt.Errorf("Can not get sandboxID")
	}
	return sandboxId, nil
}

func getPodNs(info map[string]interface{}) (string, error) {
	runtimeSpec, ok := info["runtimeSpec"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Can not get runtimeSpec")
	}
	linux, ok := runtimeSpec["linux"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Can not get linux info")
	}
	namespace, ok := linux["namespaces"].([]interface{})
	if !ok {
		return "", fmt.Errorf("Can not get namespaces")
	}
	for _, value := range namespace {
		nsInfo := value.(map[string]interface{})
		nsType, ok := nsInfo["type"]
		if !ok {
			continue
		}
		if nsType != "network" {
			continue
		}
		nsPath, ok := nsInfo["path"].(string)
		if !ok {
			return "", fmt.Errorf("Can not get network namespace path")
		}
		return strings.TrimSpace(nsPath), nil
	}

	return "", fmt.Errorf("Can not find network namespace path")
}

func processPodUpdate(old, obj interface{}) {
	defer utilruntime.HandleCrash()

	if obj.(*v1.Pod).Status.Phase != v1.PodRunning ||
		old.(*v1.Pod).Status.Phase == v1.PodRunning {
		return
	}
	podRwlock.Lock()
	defer podRwlock.Unlock()
	info := podInfo{}
	for _, cs := range obj.(*v1.Pod).Status.ContainerStatuses {
		var ifname string

		podinfo, err := getPodInfo(strings.Split(cs.ContainerID, "//")[1])
		if err != nil {
			klog.Errorf("Can not get the pod info for %s", obj.(*v1.Pod).Name, err)
		}
		if os.Getenv("CNI_VENDOR") == "FABRIC" {
			var ok bool
			info.nsPath, err = getPodNs(podinfo)
			if err != nil {
				klog.Errorf("Get pod %s ns error %v:", obj.(*v1.Pod).Name, err)
			}
			ifname, ok = obj.(*v1.Pod).Annotations["kubernetes.customized/fabric-mac"]
			if !ok {
				klog.Infof("Process pod %s update error: no kubernetes.customized/fabric-mac label", obj.(*v1.Pod).Name)
				return
			}
		} else {
			ifname, err = getPodSandboxId(podinfo)
			if err != nil {
				klog.Infof("Process pod %s update error: %v", obj.(*v1.Pod).Name, err)
				continue
			}
		}
		if getSriovInfo(ifname, &info) == true {
			info.namespace = obj.(*v1.Pod).Namespace
			podToVfIndexMap[obj.(*v1.Pod).Name] = info
			klog.Infof("Process pod %s update %v", obj.(*v1.Pod).Name, info)
		}
		updatePodStateByNicState(info, obj.(*v1.Pod).Name)
	}
}

func processPodAdd(obj interface{}) {
	defer utilruntime.HandleCrash()

	if obj.(*v1.Pod).Status.Phase != v1.PodRunning {
		return
	}
	fmt.Println(obj.(*v1.Pod).Name)
	podRwlock.Lock()
	defer podRwlock.Unlock()
	info := podInfo{}
	for _, cs := range obj.(*v1.Pod).Status.ContainerStatuses {
		var ifname string
		podinfo, err := getPodInfo(strings.Split(cs.ContainerID, "//")[1])
		if err != nil {
			klog.Errorf("Can not get the pod info for %s", obj.(*v1.Pod).Name, err)
			return
		}
		if os.Getenv("CNI_VENDOR") == "FABRIC" {
			var ok bool

			info.nsPath, err = getPodNs(podinfo)
			if err != nil {
				klog.Errorf("Get pod %s ns error %v:", obj.(*v1.Pod).Name, err)
			}
			ifname, ok = obj.(*v1.Pod).Annotations["kubernetes.customized/fabric-mac"]
			if !ok {
				klog.Infof("Process pod %s add error: no kubernetes.customized/fabric-mac label", obj.(*v1.Pod).Name)
				return
			}
		} else {
			ifname, err = getPodSandboxId(podinfo)
			if err != nil {
				klog.Infof("Process pod %s update error: %v", obj.(*v1.Pod).Name, err)
				continue
			}
		}
		if getSriovInfo(ifname, &info) == true {
			info.namespace = obj.(*v1.Pod).Namespace
			podToVfIndexMap[obj.(*v1.Pod).Name] = info
			klog.Infof("Process pod %s add %v", obj.(*v1.Pod).Name, info)
		}
		updatePodStateByNicState(info, obj.(*v1.Pod).Name)
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

func getSwitchIdByPci(pci string) (string, error) {
	netDevs, _ := sriovnet.GetNetDevicesFromPci(pci)
	for _, netDev := range netDevs {
		swIDFile := filepath.Join(nfp.NetSysDir, netDev, "phys_switch_id")
		physSwitchID, err := os.ReadFile(swIDFile)
		if err != nil || len(physSwitchID) == 0 {
			continue
		}
		return strings.TrimSpace(string(physSwitchID)), nil
	}
	return "nil", fmt.Errorf("nic not ready")
}

func init() {
	/*Wait for all nfp card ready!!!*/
	pciDevice := nfp.GetCorigineNicDevice()
	for _, pci := range pciDevice {
		for true {
			physSwitchID, err := getSwitchIdByPci(pci)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			switchIdtoPci[physSwitchID] = pci
			break
		}
	}
}
