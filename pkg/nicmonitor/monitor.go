package nicmonitor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/corigine/nic-monitor/pkg/nfp"
	"github.com/corigine/nic-monitor/pkg/util"
	"github.com/k8snetworkplumbingwg/sriovnet"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
)

var nicState map[string]bool = make(map[string]bool)
var pfPhysPortNameRe = regexp.MustCompile(`p\d+`)

var nicMonitorOnce sync.Once

const (
	MONITOR_KEEPALIVE_FAIL  uint32 = 1 << 0
	MONITOR_LINKSTATUS_FAIL uint32 = 1 << 1
)

type Monitor struct {
	pollInterval int
	hostname     string
	pciDevices   []string
	monitorState map[string]uint32
	lock         sync.Mutex
}

type NetlinkListener struct {
	fd int
	sa *syscall.SockaddrNetlink
}

func setLinkDev(link netlink.Link, enable bool, info string) error {
	if enable {
		err := netlink.LinkSetUp(link)
		if err != nil {
			klog.Errorf("%s set dev %s up error:%v", info, link.Attrs().Name, err)
			return err
		} else {
			klog.Infof("%s set dev %s up", info, link.Attrs().Name)
		}
	} else {
		err := netlink.LinkSetDown(link)
		if err != nil {
			klog.Errorf("%s set dev %s down error:%v", info, link.Attrs().Name, err)
			return err
		} else {
			klog.Infof("%s set dev %s down", info, link.Attrs().Name)
		}
	}

	return nil
}

func getVfPciInfo(devName string) (string, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)
	attr := nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF))
	req.AddData(attr)
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil {
		return "", err
	}
	for _, m := range msgs {
		infoMsg := nl.DeserializeIfInfomsg(m)
		attrs, err := nl.ParseRouteAttr(m[infoMsg.Len():])
		if err != nil {
			return "", err
		}
		for _, attr := range attrs {
			if attr.Attr.Type == unix.IFLA_IFNAME {
				if devName != string(attr.Value[:len(attr.Value)-1]) {
					break
				}
			}
			if attr.Attr.Type == unix.IFLA_PARENT_DEV_NAME {
				return string(attr.Value[:len(attr.Value)-1]), nil
			}
		}
	}
	return "", fmt.Errorf("Not pci device")
}

func setPodVfState(nsPath string, nic string, podName string, state bool) error {
	return ns.WithNetNSPath(nsPath, func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			klog.Errorf("Get link error from %s for %s:%v", nsPath, podName, err)
			return err
		}
		for _, vfLink := range links {
			if vfLink.Type() == "bond" ||
				vfLink.Attrs().Name == "lo" {
				continue
			}
			pci, err := getVfPciInfo(vfLink.Attrs().Name)
			if err != nil {
				klog.Errorf("Get pci error from %s for %s", podName, vfLink.Attrs().Name)
				continue
			}

			vfPciInfos := strings.Split(string(pci), ":")
			if len(vfPciInfos) != 3 {
				klog.Errorf("pci string error from %s for %s", podName, vfLink.Attrs().Name)
				continue
			}
			nicPciInfos := strings.Split(nic, ":")
			if len(nicPciInfos) != 3 {
				klog.Errorf("Nic pci %s info err", nic)
				continue
			}
			if vfPciInfos[0] != nicPciInfos[0] || vfPciInfos[1] != nicPciInfos[1] {
				continue
			}
			setLinkDev(vfLink, state, podName)
		}
		return nil
	})
}

func updatePodStateByNicState(info podInfo, podName string) {
	for pci, state := range nicState {
		if state == true {
			continue
		}
		setPodVfState(info.nsPath, pci, podName, false)
		for _, rep := range info.vfReps {
			if rep.pci != pci {
				continue
			}
			netlinkInfo, err := netlink.LinkByName(rep.name)
			if err != nil {
				klog.Errorf("failed to get %s netlink info", rep.name)
				return
			}
			setLinkDev(netlinkInfo, false, podName)
		}
	}
}

func setAllPodState(nic string, enable bool, vf bool) {
	podRwlock.RLock()
	defer podRwlock.RUnlock()
	for podName, info := range podToVfIndexMap {
		if vf {
			err := setPodVfState(info.nsPath, nic, podName, enable)
			if err != nil {
				klog.Errorf("failed to set %s's vf state:%v", podName, err)
			}
		}
		for _, rep := range info.vfReps {
			if rep.pci != nic {
				continue
			}
			netlinkInfo, err := netlink.LinkByName(rep.name)
			if err != nil {
				klog.Errorf("failed to get %s netlink info", rep.name)
				return
			}
			setLinkDev(netlinkInfo, enable, podName)
		}
	}
}

func setPhyState(nic string, enable bool) {
	links, err := netlink.LinkList()
	if err != nil {
		klog.Errorf("Read the link infor error %v", err)
		return
	}
	for _, link := range links {
		if link.Type() == "bond" {
			continue
		}
		if link.Attrs().Slave == nil {
			continue
		}
		if link.Attrs().Slave.SlaveType() != "bond" {
			continue
		}
		pci, err := sriovnet.GetPciFromNetDevice(link.Attrs().Name)
		if err != nil {
			continue
		}
		if pci != nic {
			continue
		}
		setLinkDev(link, enable, "")
		return
	}
}

func setBocVfState(nic string, enable bool) {
	linkDevs := util.GetBondSlave("boc0vf")
	for _, linkDev := range linkDevs {
		pci, err := sriovnet.GetPciFromNetDevice(linkDev)
		if err != nil {
			klog.Errorf("Get the pci info error for %s:%v", linkDev, err)
			continue
		}
		vfPciInfos := strings.Split(string(pci), ":")
		if len(vfPciInfos) != 3 {
			klog.Errorf("pci string error for %s", linkDev)
			continue
		}
		nicPciInfos := strings.Split(nic, ":")
		if len(nicPciInfos) != 3 {
			klog.Errorf("Nic pci %s info err", nic)
			continue
		}
		if vfPciInfos[0] != nicPciInfos[0] || vfPciInfos[1] != nicPciInfos[1] {
			continue
		}
		link, err := netlink.LinkByName(linkDev)
		if err != nil {
			klog.Errorf("Get the dev %s link error:%v", linkDev, err)
			continue
		}
		setLinkDev(link, enable, "")
		return
	}
}

func setBocVfRepState(nic string, enable bool) {
	linkDevs := util.GetBondSlave("boc0rep")
	for _, linkDev := range linkDevs {
		swIDFile := filepath.Join(nfp.NetSysDir, linkDev, "phys_switch_id")
		physSwitchID, err := os.ReadFile(swIDFile)
		if err != nil {
			klog.Errorf("Can not get the switchid for %s", linkDev)
			continue
		}

		pci, ok := switchIdtoPci[strings.TrimSpace(string(physSwitchID))]
		if !ok {
			klog.Errorf("Can not get pci for %s", linkDev)
			continue
		}
		if pci != nic {
			continue
		}
		link, err := netlink.LinkByName(linkDev)
		if err != nil {
			klog.Errorf("Get the dev %s link error:%v", linkDev, err)
			continue
		}
		setLinkDev(link, enable, "")
		return
	}
}

func setNicState(nic string, enable bool) bool {
	var aliveCount int

	if nicState[nic] == enable {
		return false
	}
	for key, value := range nicState {
		if key == nic {
			continue
		}
		if value {
			aliveCount++
		}
	}
	if !enable && aliveCount == 0 {
		klog.Errorf("failed to set nic %s to inactive due to all other nic is inactive", nic)
		return false
	}
	nicState[nic] = enable
	return true
}

func NewNicMonitor(cfg *Configuration) *Monitor {
	m := Monitor{}
	m.pciDevices = nfp.GetCorigineNicDevice()
	m.hostname = os.Getenv("NODE_NAME")
	m.pollInterval = cfg.MonitorInterval
	m.monitorState = make(map[string]uint32)
	return &m
}

func (m *Monitor) StartNicMonitor() {
	stopCh := make(chan struct{})

	if len(m.pciDevices) < 2 {
		return
	}
	nicMonitorOnce.Do(func() {
		go wait.Until(m.nicKeepAliveMonitor, time.Duration(m.pollInterval)*time.Second, stopCh)
		go m.nicLinkStatusMonitor()
	})
}

func (m *Monitor) nicKeepAliveMonitor() {
	for _, pci := range m.pciDevices {
		statusFile := filepath.Join(sysFlowerDebugDir, pci, "status")
		statusBuf, err := os.ReadFile(statusFile)
		if err != nil {
			klog.Errorf("Read the nic %s status error", pci)
			continue
		}
		if strings.TrimSpace(string(statusBuf)) == "inactive" {
			m.lock.Lock()
			m.monitorState[pci] = m.monitorState[pci] | MONITOR_KEEPALIVE_FAIL
			if setNicState(pci, false) == false {
				m.lock.Unlock()
				continue
			}
			m.lock.Unlock()
			setAllPodState(pci, false, true)
			setBocVfState(pci, false)
			setBocVfRepState(pci, false)
			setPhyState(pci, false)
			klog.Infof("nic %s changed to inactive due keepalive fail", pci)
		} else {
			m.lock.Lock()
			if m.monitorState[pci]&MONITOR_KEEPALIVE_FAIL != 0 {
				setPhyState(pci, true)
				setBocVfState(pci, true)
			}
			m.monitorState[pci] = m.monitorState[pci] & (^MONITOR_KEEPALIVE_FAIL)
			if m.monitorState[pci] != 0 {
				m.lock.Unlock()
				continue
			}
			if setNicState(pci, true) == false {
				m.lock.Unlock()
				continue
			}
			m.lock.Unlock()
			setAllPodState(pci, true, true)
			setBocVfRepState(pci, true)
			klog.Infof("nic %s changed to active due keepalive restore", pci)
		}
	}
}

func (m *Monitor) nicLinkStatusMonitor() {
	l, err := NewNetlinkListener()
	if err != nil {
		klog.Errorf("Create netlink failed.")
		return
	}
	defer syscall.Close(l.fd)
	for {
		msgs, err := l.ReadMsgs()
		if err != nil {
			klog.Errorf("Could not read msg: %v", err)
		}
		for _, msg := range msgs {
			if msg.Header.Type != syscall.RTM_NEWLINK {
				continue
			}
			ifim := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
			dev, err := netlink.LinkByIndex(int(ifim.Index))
			if err != nil {
				klog.Errorf("Get link info failed for index %d", ifim.Index)
				continue
			}
			if dev.Attrs().Slave == nil {
				continue
			}
			if dev.Attrs().Slave.SlaveType() != "bond" {
				continue
			}
			physPortNamePath := filepath.Join(nfp.NetSysDir, dev.Attrs().Name, "phys_port_name")
			physPortName, err := os.ReadFile(physPortNamePath)
			if err != nil {
				continue
			}
			if !pfPhysPortNameRe.MatchString(strings.TrimSpace(string(physPortName))) {
				continue
			}
			pci, err := sriovnet.GetPciFromNetDevice(dev.Attrs().Name)
			if err != nil {
				klog.Errorf("Get pci info failed for dev %s", dev.Attrs().Name)
				continue
			}
			if ifim.Flags&0x10000 != 0 {
				m.lock.Lock()
				m.monitorState[pci] = m.monitorState[pci] & (^MONITOR_LINKSTATUS_FAIL)
				if m.monitorState[pci] != 0 {
					m.lock.Unlock()
					continue
				}
				if setNicState(pci, true) == false {
					m.lock.Unlock()
					continue
				}
				m.lock.Unlock()
				setAllPodState(pci, true, true)
				setBocVfRepState(pci, true)
				klog.Infof("Set nic %s active due to %s up", pci, dev.Attrs().Name)
			} else {
				m.lock.Lock()
				m.monitorState[pci] = m.monitorState[pci] | MONITOR_LINKSTATUS_FAIL
				if setNicState(pci, false) == false {
					m.lock.Unlock()
					continue
				}
				m.lock.Unlock()
				setAllPodState(pci, false, false)
				setBocVfRepState(pci, false)
				klog.Infof("Set nic %s inactive due to %s down", pci, dev.Attrs().Name)
			}
		}
	}
}

func NewNetlinkListener() (*NetlinkListener, error) {
	groups := syscall.RTNLGRP_LINK
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW,
		syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("socket: %s", err)
	}
	saddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(0),
		Groups: uint32(groups),
	}

	err = syscall.Bind(s, saddr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s", err)
	}

	return &NetlinkListener{fd: s, sa: saddr}, nil
}

func (l *NetlinkListener) ReadMsgs() ([]syscall.NetlinkMessage, error) {
	defer utilruntime.HandleCrash()

	pkt := make([]byte, 4096)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}

func init() {
	pcidevices := nfp.GetCorigineNicDevice()
	for _, pci := range pcidevices {
		nicState[pci] = true
	}
}
