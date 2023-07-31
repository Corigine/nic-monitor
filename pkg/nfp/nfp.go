package nfp

// #cgo CFLAGS: -I/opt/netronome/include
// #cgo LDFLAGS: -L/opt/netronome/lib -lnfp -lnfp_common
// #include <nfp.h>
// #include <nfp_nffw.h>
/*
struct nfp_rtsym {
        const char *name;
        uint64_t addr;
        uint64_t size;
        int type;
        int16_t target;
        struct {
                uint16_t cpp_rd_act : 6;
                uint16_t cpp_rd_tok : 2;
                uint16_t cpp_wr_act : 6;
                uint16_t cpp_wr_tok : 2;
        } acttok;
        int domain;
};

#define LIST_HEAD(name, type)          \
	struct name {                  \
		struct type *lh_first; \
	}

struct nfp_device {
	unsigned int devnum;

	struct nfp_cpp_mutex *nfp_mutex;

	struct nfp_cpp *cpp;

	int dram_fd, sram_fd;

	void (*release)(struct nfp_device *dev);

	struct {
		uint64_t island_mask;
		uint64_t island_powered_mask;
		} nfp_th;

		LIST_HEAD(, nfp_device_private) private_list;
	};
*/
import "C"

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/corigine/nic-monitor/pkg/util"
	internalapi "k8s.io/cri-api/pkg/apis"

	"github.com/k8snetworkplumbingwg/sriovnet"
	utilfs "github.com/k8snetworkplumbingwg/sriovnet/pkg/utils/filesystem"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	EMU0_ISLAND                              = 24
	EMU1_ISLAND                              = 25
	EMU2_ISLAND                              = 26
	BUCKETSIZE_LW                            = 16
	ENTRYSIZE_LW                             = 64
	PAYLOADSIZE_LW                           = 64
	KEY_OFFSET                               = 5
	KEY_SIZE                                 = 32
	NFP_FLOWER_LAYER_EXT_META                = (1 << 0)
	NFP_FLOWER_LAYER_PORT                    = (1 << 1)
	NFP_FLOWER_LAYER_MAC                     = (1 << 2)
	NFP_FLOWER_LAYER_TP                      = (1 << 3)
	NFP_FLOWER_LAYER_IPV4                    = (1 << 4)
	NFP_FLOWER_LAYER_IPV6                    = (1 << 5)
	NFP_FLOWER_LAYER_VXLAN                   = (1 << 7)
	NFP_FLOWER_LAYER2_GRE                    = (1 << 0)
	NFP_FLOWER_LAYER2_QINQ                   = (1 << 4)
	NFP_FLOWER_LAYER2_GENEVE                 = (1 << 5)
	NFP_FLOWER_LAYER2_GENEVE_OP              = (1 << 6)
	NFP_FLOWER_LAYER2_TUN_IPV6               = (1 << 7)
	NFP_FLOWER_PORT_TYPE                     = (0xF << 28)
	NFP_FLOWER_PORT_TYPE_PHYS_PORT           = 0x1
	NFP_FLOWER_PORT_TYPE_PCIE_PORT           = 0x2
	NFP_FLOWER_PORT_VNIC_TYPE                = (0x7 << 11)
	NFP_FLOWER_PORT_VNIC_TYPE_VF             = 0
	NFP_FLOWER_PORT_VNIC_TYPE_PF             = 1
	NFP_FL_PORT_TYPE_TUN                     = 0x50000000
	NFP_FLOWER_TUNNEL_GRE                    = 0x1
	NFP_FLOWER_TUNNEL_VXLAN                  = 0x2
	NFP_FLOWER_TUNNEL_GENVE                  = 0x4
	NFP_FLOWER_ACTION_OPCODE_OUTPUT          = 0
	NFP_FLOWER_ACTION_OPCODE_PUSH_VLAN       = 1
	NFP_FLOWER_ACTION_OPCODE_POP_VLAN        = 2
	NFP_FLOWER_ACTION_OPCODE_PUSH_MPLS       = 3
	NFP_FLOWER_ACTION_OPCODE_POP_MPLS        = 4
	NFP_FLOWER_ACTION_OPCODE_SET_TUN_KEY     = 6
	NFP_FLOWER_ACTION_OPCODE_SET_ETH_ADDRS   = 7
	NFP_FLOWER_ACTION_OPCODE_SET_MPLS        = 8
	NFP_FLOWER_ACTION_OPCODE_SET_IPV4_ADDRS  = 9
	NFP_FLOWER_ACTION_OPCODE_SET_IPV4_FIELDS = 10
	NFP_FLOWER_ACTION_OPCODE_SET_IPV6_SRC    = 11
	NFP_FLOWER_ACTION_OPCODE_SET_IPV6_DST    = 12
	NFP_FLOWER_ACTION_OPCODE_SET_IPV6_FIELDS = 13
	NFP_FLOWER_ACTION_OPCODE_SET_UDP         = 14
	NFP_FLOWER_ACTION_OPCODE_SET_TCP         = 15
	NFP_FLOWER_ACTION_OPCODE_PRE_LAG         = 16
	NFP_FLOWER_ACTION_OPCODE_PRE_TUNNEL      = 17
	NFP_FLOWER_ACTION_OPCODE_PUSH_GENEVE     = 26

	NfpReadBufferSize  = 128 * 1024
	NFP_PCIE_LAT       = 18
	NetSysDir          = "/sys/class/net"
	PciSysDir          = "/sys/bus/pci/devices"
	NetdevPhysPortName = "phys_port_name"
	CorigineVendor     = "0x1da8"
	NetronomeVendor    = "0x19ee"
	NFP4000            = "0x4000"
	NFP6000            = "0x6000"
	TUNNEL_VXLAN       = "Vxlan"
	TUNNEL_GRE         = "Gre"
	TUNNEL_GENVE       = "Genve"
	NonPortName        = "Other"
)

var pfPhysPortNameRe = regexp.MustCompile(`p\d+`)
var pfVfPortNameRe = regexp.MustCompile(`pf(\d+)vf(\d+)`)
var repNametoPod = make(map[string]string)

type NfpDevice struct {
	devPtr        unsafe.Pointer
	PciDevice     string
	bucketSym     (*C.struct_nfp_rtsym)
	entrySym      (*C.struct_nfp_rtsym)
	payloadSym    (*C.struct_nfp_rtsym)
	fcMaskSym     (*C.struct_nfp_rtsym)
	emuNum        uint32
	fcMask        []uint32
	bucketBuffer  []uint32
	bucketValid   []bool
	nfpLock       sync.Mutex
	entryBuffer   []uint32
	entryValid    []bool
	payloadBuffer []uint32
	payloadValid  []bool
	devMapCache   map[uint32]string
	devMapLock    sync.RWMutex
}

type macLayer struct {
	dstMac  []byte
	srcMac  []byte
	mplsLse uint32
}

type metaTci struct {
	keyLayer uint8
	tci      uint16
}

type qinqLayer struct {
	outerTpid uint16
	outerTci  uint16
	innerTpid uint16
	innerTci  uint16
}

type tpLayer struct {
	srcPort uint16
	dstPort uint16
}

type ipLayer struct {
	srcIp []byte
	dstIp []byte
	proto uint8
	tos   uint8
	ttl   uint8
	flag  uint8
}

type tunnelLayer struct {
	srcIp    []byte
	dstIp    []byte
	tunnelId uint32
	tos      uint8
	ttl      uint8
}

type FlowEntryKey struct {
	devName   string
	metaKey   metaTci
	qinqKey   qinqLayer
	l2Key     macLayer
	ipKey     ipLayer
	l4Key     tpLayer
	tunnelKey tunnelLayer
}

type FlowEntryActionOutPort struct {
	opCode  uint8
	devName string
}

type FlowEntryActionSetEth struct {
	dstMac     []byte
	dstMacMask []byte
	srcMac     []byte
	srcMacMask []byte
}

type FlowEntryActionSetTunnel struct {
	tunnelType uint8
	tunnelId   uint64
	ttl        uint8
	tos        uint8
	proto      uint16
	dst        []byte
}

type FlowEntryActionSetIp struct {
	srcIp     []byte
	srcIpMask []byte
	dstIp     []byte
	dstIpMask []byte
	ttl       uint8
	ttlMask   uint8
	tos       uint8
	tosMask   uint8
}

type FlowEntryActionSetTp struct {
	L4srcPort     uint16
	L4srcPortMask uint16
	L4dstPort     uint16
	L4dstPortMask uint16
}

type FlowEntryAction struct {
	outPort   FlowEntryActionOutPort
	setEth    FlowEntryActionSetEth
	setTunnel FlowEntryActionSetTunnel
	setIp     FlowEntryActionSetIp
	setTp     FlowEntryActionSetTp
}
type FlowEntry struct {
	key       FlowEntryKey
	mask      FlowEntryKey
	actions   FlowEntryAction
	pktCount  uint64
	byteCount uint64
}

type FlowFilter struct {
	DevName   string
	SrcIp     string
	DstIp     string
	L4SrcPort uint16
	L4DstPort uint16
}

func GetCorigineNicDevice() []string {
	var corigineNicDevices []string
	devices, err := utilfs.Fs.ReadDir(PciSysDir)
	if err != nil {
		klog.Warningf("Can not open the pci sys dir\n")
	}
	for _, device := range devices {
		deviceDir := filepath.Join(PciSysDir, device.Name())
		vendorDir := filepath.Join(deviceDir, "vendor")
		vendorName, err := utilfs.Fs.ReadFile(vendorDir)
		if err != nil || ((strings.TrimSpace(string(vendorName)) != CorigineVendor) &&
			(strings.TrimSpace(string(vendorName)) != NetronomeVendor)) {
			continue
		}
		deviceIdDir := filepath.Join(deviceDir, "device")
		deviceName, err := utilfs.Fs.ReadFile(deviceIdDir)
		if err != nil || (strings.TrimSpace(string(deviceName)) != NFP4000 &&
			strings.TrimSpace(string(deviceName)) != NFP6000) {
			continue
		}
		corigineNicDevices = append(corigineNicDevices, device.Name())
	}
	return corigineNicDevices
}

func (flow *FlowEntry) PrintEntryInfo() {
	fmt.Println("Key:")
	if flow.key.metaKey.keyLayer&NFP_FLOWER_LAYER_PORT != 0 {
		fmt.Printf("  %-16s%s\n", "Port:", flow.key.devName)
	}
	if flow.key.metaKey.keyLayer&NFP_FLOWER_LAYER_MAC != 0 {
		if util.MaskIsMaskAll(flow.mask.l2Key.dstMac) {
			fmt.Printf("  %-16s%s\n", "Dst Mac:", net.HardwareAddr(flow.key.l2Key.dstMac).String())
		} else if util.MaskIsMaskNone(flow.mask.l2Key.dstMac) == false {
			fmt.Printf("  %-16s%s/%s\n", "Dst Mac:", net.HardwareAddr(flow.key.l2Key.dstMac).String(),
				net.HardwareAddr(flow.mask.l2Key.dstMac).String())
		}
		if util.MaskIsMaskAll(flow.mask.l2Key.srcMac) {
			fmt.Printf("  %-16s%s\n", "Src Mac:", net.HardwareAddr(flow.key.l2Key.srcMac).String())
		} else if util.MaskIsMaskNone(flow.mask.l2Key.srcMac) == false {
			fmt.Printf("  %-16s%s/%s\n", "Src Mac:", net.HardwareAddr(flow.key.l2Key.srcMac).String(),
				net.HardwareAddr(flow.mask.l2Key.srcMac).String())
		}
	}
	if flow.key.metaKey.keyLayer&NFP_FLOWER_LAYER_IPV4 != 0 {
		if flow.key.ipKey.proto != 0 {
			fmt.Printf("  %-16s%d\n", "IP proto:", flow.key.ipKey.proto)
		}
		if util.MaskIsMaskAll(flow.mask.ipKey.srcIp) {
			fmt.Printf("  %-16s%s\n", "Src IP:", net.IP(flow.key.ipKey.srcIp).String())
		} else if util.MaskIsMaskNone(flow.mask.ipKey.srcIp) == false {
			fmt.Printf("  %-16s%s/%s\n", "Src IP:", net.IP(flow.key.ipKey.srcIp).String(),
				net.IP(flow.mask.ipKey.srcIp).String())
		}

		if util.MaskIsMaskAll(flow.mask.ipKey.dstIp) {
			fmt.Printf("  %-16s%s\n", "Dst IP:", net.IP(flow.key.ipKey.dstIp).String())
		} else if util.MaskIsMaskNone(flow.mask.ipKey.dstIp) == false {
			fmt.Printf("  %-16s%s/%s\n", "Dst IP:", net.IP(flow.key.ipKey.dstIp).String(),
				net.IP(flow.mask.ipKey.srcIp).String())
		}
	}
	if flow.key.metaKey.keyLayer&NFP_FLOWER_LAYER_TP != 0 {
		if flow.mask.l4Key.srcPort == 0xFFFF {
			fmt.Printf("  %-16s%d\n", "L4 Src Port:", flow.key.l4Key.srcPort)
		} else if flow.mask.l4Key.srcPort != 0 {
			fmt.Printf("  %-16s%d/0x%x\n", "L4 Src Port:", flow.key.l4Key.srcPort, flow.mask.l4Key.srcPort)
		}
		if flow.mask.l4Key.dstPort == 0xFFFF {
			fmt.Printf("  %-16s%d\n", "L4 Dst Port:", flow.key.l4Key.dstPort)
		} else if flow.mask.l4Key.dstPort != 0 {
			fmt.Printf("  %-16s%d/0x%x\n", "L4 Dst Port:", flow.key.l4Key.dstPort, flow.mask.l4Key.dstPort)
		}
	}
	if flow.key.metaKey.keyLayer&NFP_FLOWER_LAYER_VXLAN != 0 {
		if flow.key.devName == TUNNEL_VXLAN {
			fmt.Printf("  %-16s%s\n", "Tunnel Src IP:", net.IP(flow.key.tunnelKey.srcIp).String())
			fmt.Printf("  %-16s%s\n", "Tunnel Dst IP:", net.IP(flow.key.tunnelKey.dstIp).String())
			fmt.Printf("  %-16s%d\n", "Tunnel Id:", flow.key.tunnelKey.tunnelId)
		}
	}
	fmt.Println()
	fmt.Println("Action:")
	if flow.actions.outPort.devName != "" {
		if flow.key.devName == TUNNEL_VXLAN {
			fmt.Printf("  %-16s\n", "Tunnel Decap")
		}
		fmt.Printf("  %-16s%s\n", "Redirect Port:", flow.actions.outPort.devName)
	}
	if flow.actions.setTunnel.tunnelType == NFP_FLOWER_TUNNEL_VXLAN {
		fmt.Printf("  %-16s%s\n", "Tunnel Encap:", TUNNEL_VXLAN)
		fmt.Printf("  %-16s%s\n", "  Dst IP:", net.IP(flow.actions.setTunnel.dst).String())
		fmt.Printf("  %-16s%d\n", "  Tunnel Id:", flow.actions.setTunnel.tunnelId)
		fmt.Printf("  %-16s%d\n", "  Ttl:", flow.actions.setTunnel.ttl)
	}

	if util.MaskIsMaskAll(flow.actions.setEth.dstMacMask) {
		fmt.Printf("  %-16s%s\n", "Set Dst Mac:", net.HardwareAddr(flow.actions.setEth.dstMac).String())
	} else if util.MaskIsMaskNone(flow.actions.setEth.dstMacMask) == false {
		fmt.Printf("  %-16s%s/%s\n", "Set Dst Mac:", net.HardwareAddr(flow.actions.setEth.dstMac).String(),
			net.HardwareAddr(flow.actions.setEth.dstMacMask).String())
	}
	if util.MaskIsMaskAll(flow.actions.setEth.srcMacMask) {
		fmt.Printf("  %-16s%s\n", "Set Src Mac:", net.HardwareAddr(flow.actions.setEth.srcMac).String())
	} else if util.MaskIsMaskNone(flow.actions.setEth.srcMacMask) == false {
		fmt.Printf("  %-16s%s/%s\n", "Set Src Mac:", net.HardwareAddr(flow.actions.setEth.srcMac).String(),
			net.HardwareAddr(flow.actions.setEth.srcMacMask).String())
	}

	if util.MaskIsMaskAll(flow.actions.setIp.srcIpMask) {
		fmt.Printf("  %-16s%s\n", "Set Src Ip:", net.IP(flow.actions.setIp.srcIp).String())
	} else if util.MaskIsMaskNone(flow.actions.setIp.srcIpMask) == false {
		fmt.Printf("  %-16s%s/%s\n", "Set Src IP:", net.IP(flow.actions.setIp.srcIp).String(),
			net.IP(flow.actions.setIp.srcIpMask).String())
	}
	if util.MaskIsMaskAll(flow.actions.setIp.dstIpMask) {
		fmt.Printf("  %-16s%s\n", "Set Dst Ip:", net.IP(flow.actions.setIp.dstIp).String())
	} else if util.MaskIsMaskNone(flow.actions.setIp.dstIpMask) == false {
		fmt.Printf("  %-16s%s/%s\n", "Set Src IP:", net.IP(flow.actions.setIp.dstIp).String(),
			net.IP(flow.actions.setIp.dstIpMask).String())
	}
	if flow.actions.setIp.tosMask == 0xFF {
		fmt.Printf("  %-16s%d\n", "Set Ip tos:", flow.actions.setIp.tos)
	} else if flow.actions.setIp.tosMask != 0 {
		fmt.Printf("  %-16s%d/0x%x\n", "Set Ip ttl:", flow.actions.setIp.tos,
			flow.actions.setIp.tosMask)
	}

	if flow.actions.setIp.ttlMask == 0xFF {
		fmt.Printf("  %-16s%d\n", "Set Ip ttl:", flow.actions.setIp.ttl)
	} else if flow.actions.setIp.ttlMask != 0 {
		fmt.Printf("  %-16s%d/0x%x\n", "Set Ip ttl:", flow.actions.setIp.ttl,
			flow.actions.setIp.ttlMask)
	}

	if flow.actions.setTp.L4dstPortMask == 0xFFFF {
		fmt.Printf("  %-16s%d\n", "Set L4dst Port:", flow.actions.setTp.L4dstPort)
	} else if flow.actions.setTp.L4dstPortMask != 0 {
		fmt.Printf("  %-16s%d/0x%x\n", "Set L4dst Port:", flow.actions.setTp.L4dstPort,
			flow.actions.setTp.L4dstPortMask)
	}

	if flow.actions.setTp.L4srcPortMask == 0xFFFF {
		fmt.Printf("  %-16s%d\n", "Set L4src Port:", flow.actions.setTp.L4srcPort)
	} else if flow.actions.setTp.L4srcPortMask != 0 {
		fmt.Printf("  %-16s%d/0x%x\n", "Set L4src Port:", flow.actions.setTp.L4srcPort,
			flow.actions.setTp.L4srcPortMask)
	}
}
func NewNfpDevice(devNo uint, pciDevice string) *NfpDevice {
	devPtr := C.nfp_device_open(C.uint(devNo))
	if devPtr == nil {
		util.LogFatalAndExit(nil, "Can not open nfp device %d", devNo)
	}

	return &NfpDevice{devPtr: unsafe.Pointer(devPtr), PciDevice: pciDevice}
}

func (dev *NfpDevice) Close() {
	C.nfp_device_close((*C.struct_nfp_device)(dev.devPtr))
}

func (dev *NfpDevice) GetLatancy() (uint32, error) {
	var nfpSym (*C.struct_nfp_rtsym)
	var lat uint32
	emuIsland := EMU0_ISLAND

	symName := C.CString("PKT_LAT_DATA_GLOB")
	defer C.free(unsafe.Pointer(symName))

	nfpSym = C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), symName)
	if nfpSym == nil {
		return 0, fmt.Errorf("Can not get nic latancy symbol.")
	}

	C.nfp_emem_read((*C.struct_nfp_device)(dev.devPtr),
		C.int(emuIsland),
		(unsafe.Pointer)(&lat),
		4,
		(C.ulonglong)(nfpSym.addr))
	if (lat & 0xFF000000) == 0 {
		return 0, fmt.Errorf("The nic latancy value is invailid.")
	}

	lat = (lat&0xFFFFFF)*16/1000 + NFP_PCIE_LAT

	return lat, nil
}
func (dev *NfpDevice) GetTemperature() (float32, error) {
	var temp, tempErr float32
	var raw uint32

	err := C.nfp_temp((*C.struct_nfp_device)(dev.devPtr), (*C.uint)(&raw),
		(*C.float)(&temp), (*C.float)(&tempErr))
	if int32(C.int(err)) != 0 {
		return temp, fmt.Errorf("error code %d", int32(C.int(err)))
	}

	return temp, nil
}

func (dev *NfpDevice) GetBucketCount(emmu uint32) int {
	num := int(dev.bucketSym.size) / (BUCKETSIZE_LW * 4)

	return num
}

func (dev *NfpDevice) getPhyPortRepName(portIndex uint32) (string, error) {
	netDevs, _ := sriovnet.GetNetDevicesFromPci(dev.PciDevice)
	if portIndex > 0 {
		portIndex = 1
	}
	for _, netDev := range netDevs {
		devicePortNameFile := filepath.Join(NetSysDir, netDev, NetdevPhysPortName)
		physPortName, err := utilfs.Fs.ReadFile(devicePortNameFile)

		if err != nil ||
			!pfPhysPortNameRe.MatchString(strings.TrimSpace(string(physPortName))) {
			continue
		}
		index, err := strconv.Atoi(strings.TrimSpace(string(physPortName[1:])))
		if err != nil || uint32(index) != portIndex {
			continue
		}

		return strings.TrimSpace(netDev), nil
	}
	err := fmt.Errorf("Can not find the phys port %d on %s ", portIndex, dev.PciDevice)
	return "", err
}

func (dev *NfpDevice) GetVfRepPortName(portIndex uint32) (string, error) {

	uplink, err := dev.getPhyPortRepName(0)
	if err != nil {
		return "", err
	}
	return sriovnet.GetVfRepresentor(uplink, int(portIndex))
}

func (dev *NfpDevice) GetDevNameByPortIndex(port uint32) (string, error) {
	var portIndex uint32
	var err error

	if port&0xFFFFFFF0 == 0x50000000 {
		if port&0xF == NFP_FLOWER_TUNNEL_GENVE {
			return TUNNEL_GENVE, nil
		}
		if port&0xF == NFP_FLOWER_TUNNEL_VXLAN {
			return TUNNEL_VXLAN, nil
		}
		if port&0xF == NFP_FLOWER_TUNNEL_GRE {
			return TUNNEL_GRE, nil
		}
		return "", fmt.Errorf("Can not parse the tunnel port %x", port)
	}

	portType := port >> 28 & 0xF
	if portType == NFP_FLOWER_PORT_TYPE_PHYS_PORT {
		portIndex = (port & 0xFF)
	} else if portType == NFP_FLOWER_PORT_TYPE_PCIE_PORT {
		portIndex = (port >> 6 & 0x3F)
	} else {
		return "", fmt.Errorf("Can not parse the flow port %x", port)
	}
	dev.devMapLock.RLock()
	devName, ok := dev.devMapCache[portIndex]
	dev.devMapLock.RUnlock()
	if !ok {
		if portType == NFP_FLOWER_PORT_TYPE_PHYS_PORT {
			devName, err = dev.getPhyPortRepName(portIndex)
		} else {
			devName, err = dev.GetVfRepPortName(portIndex)
		}
		dev.devMapLock.Lock()
		dev.devMapCache[portIndex] = devName
		dev.devMapLock.Unlock()
	}
	return devName, err
}

func (dev *NfpDevice) pareFlowEntryKey(entryBuffer []uint32, flowEntry *FlowEntry) error {
	var layers uint8 = 0
	var ext_layers uint32 = 0

	layers = uint8(entryBuffer[KEY_OFFSET+1] >> 24)
	flowEntry.key.metaKey.keyLayer = layers
	i := KEY_OFFSET + 2

	maskId := uint8(entryBuffer[KEY_OFFSET+1] >> 16 & 0xFF)
	maskindex := uint32(maskId)*64 + 4

	if layers&NFP_FLOWER_LAYER_EXT_META != 0 {
		ext_layers = entryBuffer[i]
		i += 1
	}
	if layers&NFP_FLOWER_LAYER_PORT != 0 {
		portIndex := entryBuffer[i]
		devName, err := dev.GetDevNameByPortIndex(portIndex)
		if err != nil {
			return err
		}
		podName, ok := repNametoPod[devName]
		if ok {
			devName = podName
		}
		flowEntry.key.devName = devName

		i += 1
		maskindex += 1
	}
	if layers&NFP_FLOWER_LAYER_MAC != 0 {
		flowEntry.key.l2Key.dstMac = binary.BigEndian.AppendUint32(flowEntry.key.l2Key.dstMac, entryBuffer[i])
		flowEntry.key.l2Key.dstMac = binary.BigEndian.AppendUint16(flowEntry.key.l2Key.dstMac, uint16(entryBuffer[i+1]>>16))
		flowEntry.mask.l2Key.dstMac = binary.BigEndian.AppendUint32(flowEntry.mask.l2Key.dstMac, dev.fcMask[maskindex])
		flowEntry.mask.l2Key.dstMac = binary.BigEndian.AppendUint16(flowEntry.mask.l2Key.dstMac, uint16(dev.fcMask[maskindex+1]>>16))
		flowEntry.key.l2Key.srcMac = binary.BigEndian.AppendUint16(flowEntry.key.l2Key.srcMac, uint16(entryBuffer[i+1]))
		flowEntry.key.l2Key.srcMac = binary.BigEndian.AppendUint32(flowEntry.key.l2Key.srcMac, entryBuffer[i+2])
		flowEntry.mask.l2Key.srcMac = binary.BigEndian.AppendUint16(flowEntry.mask.l2Key.srcMac,
			uint16(dev.fcMask[maskindex+1]))
		flowEntry.mask.l2Key.srcMac = binary.BigEndian.AppendUint32(flowEntry.mask.l2Key.srcMac,
			dev.fcMask[maskindex+2])
		i += 4
		maskindex += 4
	}
	if ext_layers&NFP_FLOWER_LAYER2_QINQ != 0 {
		i += 2
		maskindex += 2
	}
	if layers&NFP_FLOWER_LAYER_TP != 0 {
		flowEntry.key.l4Key.srcPort = uint16(entryBuffer[i] >> 16)
		flowEntry.mask.l4Key.srcPort = uint16(dev.fcMask[maskindex] >> 16)
		flowEntry.key.l4Key.dstPort = uint16(entryBuffer[i])
		flowEntry.mask.l4Key.dstPort = uint16(dev.fcMask[maskindex])
		i += 1
		maskindex += 1
	}
	if layers&NFP_FLOWER_LAYER_IPV4 != 0 {
		flowEntry.key.ipKey.proto = uint8(entryBuffer[i] >> 16 & 0xFF)
		flowEntry.mask.ipKey.proto = uint8(dev.fcMask[maskindex] >> 16 & 0xFF)
		flowEntry.key.ipKey.srcIp = binary.BigEndian.AppendUint32(flowEntry.key.ipKey.srcIp, entryBuffer[i+1])
		flowEntry.mask.ipKey.srcIp = binary.BigEndian.AppendUint32(flowEntry.mask.ipKey.srcIp, dev.fcMask[maskindex+1])
		flowEntry.key.ipKey.dstIp = binary.BigEndian.AppendUint32(flowEntry.key.ipKey.dstIp, entryBuffer[i+2])
		i += 3
		maskindex += 3
	}

	if ext_layers&NFP_FLOWER_LAYER2_GRE != 0 {
		if ext_layers&NFP_FLOWER_LAYER2_TUN_IPV6 != 0 {
			i += 12
		} else {
			i += 6
		}
	}
	if (layers&NFP_FLOWER_LAYER_VXLAN != 0) ||
		(ext_layers&NFP_FLOWER_LAYER2_GENEVE != 0) {
		if ext_layers&NFP_FLOWER_LAYER2_TUN_IPV6 != 0 {
			i += 11
		} else {
			if ext_layers&NFP_FLOWER_LAYER2_GENEVE != 0 {
				i += 5
			} else {
				flowEntry.key.tunnelKey.srcIp = binary.BigEndian.AppendUint32(flowEntry.key.tunnelKey.srcIp, entryBuffer[i])
				flowEntry.key.tunnelKey.dstIp = binary.BigEndian.AppendUint32(flowEntry.key.tunnelKey.dstIp, entryBuffer[i+1])
				flowEntry.key.tunnelKey.tunnelId = entryBuffer[i+4] >> 8
			}
		}
	}

	return nil
}

func (dev *NfpDevice) parseOutPort(payloadBuffer []uint32, flowEntry *FlowEntry) error {
	devName, err := dev.GetDevNameByPortIndex(payloadBuffer[1])
	if err != nil {
		return err
	}
	podName, ok := repNametoPod[devName]
	if ok {
		devName = podName
	}
	flowEntry.actions.outPort.devName = devName
	return nil
}

func (dev *NfpDevice) parseSetEthAddress(payloadBuffer []uint32, flowEntry *FlowEntry) error {
	flowEntry.actions.setEth.dstMacMask =
		binary.BigEndian.AppendUint32(flowEntry.actions.setEth.dstMacMask, payloadBuffer[1])
	flowEntry.actions.setEth.dstMacMask =
		binary.BigEndian.AppendUint16(flowEntry.actions.setEth.dstMacMask, uint16(payloadBuffer[2]>>16))
	flowEntry.actions.setEth.srcMacMask =
		binary.BigEndian.AppendUint16(flowEntry.actions.setEth.srcMac, uint16(payloadBuffer[2]))
	flowEntry.actions.setEth.srcMacMask =
		binary.BigEndian.AppendUint32(flowEntry.actions.setEth.srcMac, payloadBuffer[3])
	flowEntry.actions.setEth.dstMac =
		binary.BigEndian.AppendUint32(flowEntry.actions.setEth.dstMac, payloadBuffer[4])
	flowEntry.actions.setEth.dstMac =
		binary.BigEndian.AppendUint16(flowEntry.actions.setEth.dstMac, uint16(payloadBuffer[5]>>16))
	flowEntry.actions.setEth.srcMac =
		binary.BigEndian.AppendUint16(flowEntry.actions.setEth.srcMac, uint16(payloadBuffer[5]))
	flowEntry.actions.setEth.srcMac =
		binary.BigEndian.AppendUint32(flowEntry.actions.setEth.srcMac, payloadBuffer[6])

	return nil
}

func (dev *NfpDevice) parseSetTunel(payloadBuffer []uint32, flowEntry *FlowEntry) error {
	flowEntry.actions.setTunnel.tunnelId = (uint64(payloadBuffer[1]) << 32) | uint64(payloadBuffer[2])
	flowEntry.actions.setTunnel.tunnelType = uint8(payloadBuffer[3] >> 4 & 0xF)
	flowEntry.actions.setTunnel.ttl = uint8(payloadBuffer[4] >> 8 & 0xFF)
	flowEntry.actions.setTunnel.tos = uint8(payloadBuffer[4] & 0xFF)
	flowEntry.actions.setTunnel.proto = uint16(payloadBuffer[6] & 0xFFFF)
	return nil
}

func (dev *NfpDevice) parseSetIp(payloadBuffer []uint32, flowEntry *FlowEntry) error {

	flowEntry.actions.setIp.srcIpMask =
		binary.BigEndian.AppendUint32(flowEntry.actions.setIp.srcIpMask, payloadBuffer[1])
	flowEntry.actions.setIp.srcIp =
		binary.BigEndian.AppendUint32(flowEntry.actions.setIp.srcIp, payloadBuffer[2])
	flowEntry.actions.setIp.dstIpMask =
		binary.BigEndian.AppendUint32(flowEntry.actions.setIp.dstIpMask, payloadBuffer[3])
	flowEntry.actions.setIp.dstIp =
		binary.BigEndian.AppendUint32(flowEntry.actions.setIp.dstIp, payloadBuffer[4])

	return nil
}

func (dev *NfpDevice) parseSetIpField(payloadBuffer []uint32, flowEntry *FlowEntry) error {

	flowEntry.actions.setIp.ttlMask = uint8((payloadBuffer[0] >> 8 & 0xFF))
	flowEntry.actions.setIp.tosMask = uint8((payloadBuffer[0] & 0xFF))
	flowEntry.actions.setIp.ttl = uint8(payloadBuffer[1] >> 24 & 0xFF)
	flowEntry.actions.setIp.tos = uint8(payloadBuffer[1] >> 16 & 0xFF)

	return nil
}

func (dev *NfpDevice) parseSetTp(payloadBuffer []uint32, flowEntry *FlowEntry) error {

	flowEntry.actions.setTp.L4srcPortMask = uint16((payloadBuffer[1] >> 16 & 0xFFFF))
	flowEntry.actions.setTp.L4dstPortMask = uint16((payloadBuffer[1] & 0xFFFF))
	flowEntry.actions.setTp.L4srcPort = uint16((payloadBuffer[2] >> 16 & 0xFFFF))
	flowEntry.actions.setTp.L4dstPort = uint16((payloadBuffer[2] & 0xFFFF))

	return nil
}

func (dev *NfpDevice) parsePreTunel(payloadBuffer []uint32, flowEntry *FlowEntry) error {

	flowEntry.actions.setTunnel.dst =
		binary.BigEndian.AppendUint32(flowEntry.actions.setTunnel.dst, payloadBuffer[1])
	if uint16(payloadBuffer[4]>>16&0xFFFF) != 0 {
		flowEntry.actions.setTunnel.dst =
			binary.BigEndian.AppendUint32(flowEntry.actions.setTunnel.dst, payloadBuffer[2])
		flowEntry.actions.setTunnel.dst =
			binary.BigEndian.AppendUint32(flowEntry.actions.setTunnel.dst, payloadBuffer[3])
		flowEntry.actions.setTunnel.dst =
			binary.BigEndian.AppendUint32(flowEntry.actions.setTunnel.dst, payloadBuffer[4])
	}
	return nil
}

func (dev *NfpDevice) pareFlowEntryAction(payloadBuffer []uint32, flowEntry *FlowEntry) error {
	var i uint32 = 4
	var parsePayload uint32 = 0
	totalPayloadLen := payloadBuffer[0] & 0xFF

	for parsePayload < totalPayloadLen {
		optCode := payloadBuffer[i] >> 24 & 0xFF
		actLen := payloadBuffer[i] >> 16 & 0xFF
		if actLen == 0 {
			return fmt.Errorf("Flow entry parse invalid action len")
		}
		switch optCode {
		case NFP_FLOWER_ACTION_OPCODE_OUTPUT:
			if actLen != 2 {
				return fmt.Errorf("Flow entry parse invalid output action")
			}
			err := dev.parseOutPort(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_SET_ETH_ADDRS:
			if actLen != 7 {
				return fmt.Errorf("Flow entry parse invalid set eth address action")
			}

			err := dev.parseSetEthAddress(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_SET_TUN_KEY:
			if actLen != 7 {
				return fmt.Errorf("Flow entry parse invalid set tunnel action")
			}
			err := dev.parseSetTunel(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_PRE_TUNNEL:
			if actLen != 5 {
				return fmt.Errorf("Flow entry parse invalid pre tunnel action")
			}
			err := dev.parsePreTunel(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_SET_IPV4_ADDRS:
			if actLen != 5 {
				return fmt.Errorf("Flow entry parse invalid set ip action")
			}
			err := dev.parseSetIp(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_SET_IPV4_FIELDS:
			if actLen != 2 {
				return fmt.Errorf("Flow entry parse invalid set ip filed action")
			}
			err := dev.parseSetIpField(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		case NFP_FLOWER_ACTION_OPCODE_SET_UDP:
		case NFP_FLOWER_ACTION_OPCODE_SET_TCP:
			if actLen != 3 {
				return fmt.Errorf("Flow entry parse invalid set l4port filed action")
			}
			err := dev.parseSetTp(payloadBuffer[i:i+actLen], flowEntry)
			if err != nil {
				return err
			}
			break
		default:
			klog.Warningf("Flow entry can not support parse %d action", optCode)
			break
		}
		i += actLen
		parsePayload += actLen
	}

	return nil
}

func (dev *NfpDevice) parseFlowEntryByNfpBuffer(entryBuffer []uint32, payloadBuffer []uint32, filter *FlowFilter) (*FlowEntry, error) {
	var flowEntry FlowEntry
	var err error

	flowEntry.pktCount = (uint64)(entryBuffer[60]) | (uint64)(entryBuffer[61])<<32
	flowEntry.byteCount = (uint64)(entryBuffer[62]) | (uint64)(entryBuffer[63])<<32
	err = dev.pareFlowEntryKey(entryBuffer, &flowEntry)
	if err != nil {
		return nil, err
	}

	err = dev.pareFlowEntryAction(payloadBuffer, &flowEntry)
	if err != nil {
		return nil, err
	}

	if filter != nil && filter.DevName != "" {
		if filter.DevName != flowEntry.key.devName &&
			filter.DevName != flowEntry.actions.outPort.devName {
			return nil, fmt.Errorf("Flow filter devname  %s not match", filter.DevName)
		}
	}
	if filter != nil && filter.L4DstPort != 0 {
		if flowEntry.key.l4Key.dstPort != filter.L4DstPort {
			return nil, fmt.Errorf("Flow filter L4 Dst Port  %d not match", filter.L4DstPort)
		}
	}
	if filter != nil && filter.L4SrcPort != 0 {
		if flowEntry.key.l4Key.srcPort != filter.L4SrcPort {
			return nil, fmt.Errorf("Flow filter L4 Src Port  %d not match", filter.L4SrcPort)
		}
	}
	if filter != nil && filter.SrcIp != "" {
		if filter.SrcIp != net.IP(flowEntry.key.ipKey.srcIp).String() {
			return nil, fmt.Errorf("Flow filter L4 Src IP  %s not match", filter.SrcIp)
		}
	}
	if filter != nil && filter.DstIp != "" {
		if filter.DstIp != net.IP(flowEntry.key.ipKey.dstIp).String() {
			return nil, fmt.Errorf("Flow filter L4 Dst IP  %s not match", filter.DstIp)
		}
	}

	return &flowEntry, nil
}

func (dev *NfpDevice) getFlowEntryByBucketHash(emmu uint32, index uint32, hash0 bool, filter *FlowFilter) []*FlowEntry {
	var flowEntrys []*FlowEntry

	bucketNum := (uint32)(dev.bucketSym.size) / (BUCKETSIZE_LW * 4)
	if hash0 == false {
		index = bucketNum + index - 1
	}

	for {
		entryBuffer := dev.getNfpEntryBuffer(emmu, index)
		payloadBuffer := dev.getNfpPayloadBuffer(emmu, index)

		flow, err := dev.parseFlowEntryByNfpBuffer(entryBuffer, payloadBuffer, filter)
		if err == nil {
			flowEntrys = append(flowEntrys, flow)
		}

		collisionIndex := (entryBuffer[0] & 0xFFFFFF00) >> 8
		if collisionIndex <= 0 {
			break
		}

		index = collisionIndex + bucketNum - 1
	}

	return flowEntrys
}

func (dev *NfpDevice) getNfpBucketBuffer(emmu uint32, index uint32) []uint32 {
	emuIsland := EMU0_ISLAND
	nfpBufferIndex := index * BUCKETSIZE_LW * 4 / NfpReadBufferSize
	if dev.bucketValid[nfpBufferIndex] == false {
		dev.nfpLock.Lock()
		defer dev.nfpLock.Unlock()

		if dev.bucketValid[nfpBufferIndex] == false {
			var bucketReadAddr uint64
			bucketReadAddr = uint64(dev.bucketSym.addr) +
				uint64(nfpBufferIndex*NfpReadBufferSize)
			C.nfp_emem_read((*C.struct_nfp_device)(dev.devPtr),
				C.int(emuIsland),
				(unsafe.Pointer)(&dev.bucketBuffer[nfpBufferIndex*NfpReadBufferSize/4]),
				NfpReadBufferSize,
				(C.ulonglong)(bucketReadAddr))
			dev.bucketValid[nfpBufferIndex] = true
		}
	}

	return dev.bucketBuffer[index*BUCKETSIZE_LW : (index+1)*BUCKETSIZE_LW]
}

func (dev *NfpDevice) getNfpEntryBuffer(emmu uint32, index uint32) []uint32 {
	emuIsland := EMU0_ISLAND

	nfpBufferIndex := index * ENTRYSIZE_LW * 4 / NfpReadBufferSize
	if dev.entryValid[nfpBufferIndex] == false {
		dev.nfpLock.Lock()
		defer dev.nfpLock.Unlock()

		var entryReadAddr uint64
		if dev.entryValid[nfpBufferIndex] == false {
			entryReadAddr = uint64(dev.entrySym.addr) +
				uint64(nfpBufferIndex*NfpReadBufferSize)
			C.nfp_emem_read((*C.struct_nfp_device)(dev.devPtr),
				C.int(emuIsland),
				(unsafe.Pointer)(&dev.entryBuffer[nfpBufferIndex*NfpReadBufferSize/4]),
				NfpReadBufferSize,
				(C.ulonglong)(entryReadAddr))
			dev.entryValid[nfpBufferIndex] = true
		}
	}

	return dev.entryBuffer[index*ENTRYSIZE_LW : (index+1)*ENTRYSIZE_LW]
}

func (dev *NfpDevice) getNfpPayloadBuffer(emmu uint32, index uint32) []uint32 {
	emuIsland := EMU0_ISLAND

	nfpBufferIndex := index * PAYLOADSIZE_LW * 4 / NfpReadBufferSize
	if dev.payloadValid[nfpBufferIndex] == false {
		dev.nfpLock.Lock()
		defer dev.nfpLock.Unlock()
		var payloadReadAddr uint64

		if dev.payloadValid[nfpBufferIndex] == false {
			payloadReadAddr = uint64(dev.payloadSym.addr) +
				uint64(nfpBufferIndex*NfpReadBufferSize)
			C.nfp_emem_read((*C.struct_nfp_device)(dev.devPtr),
				C.int(emuIsland),
				(unsafe.Pointer)(&dev.payloadBuffer[nfpBufferIndex*NfpReadBufferSize/4]),
				NfpReadBufferSize,
				(C.ulonglong)(payloadReadAddr))
			dev.payloadValid[nfpBufferIndex] = true
		}
	}

	return dev.payloadBuffer[index*PAYLOADSIZE_LW : (index+1)*PAYLOADSIZE_LW]
}

func (dev *NfpDevice) getFlowEntryByBucket(emmu uint32, index int, filter *FlowFilter) []*FlowEntry {
	var flowEntrys []*FlowEntry

	bucketReadAddr := uint64(dev.bucketSym.addr) + uint64((BUCKETSIZE_LW*4)*index)
	if bucketReadAddr > uint64(dev.bucketSym.addr)+uint64(dev.bucketSym.size) {
		klog.Errorf("The index %d is overflow when get flow entry!")
		return nil
	}

	defer func() {
		if err := recover(); err != nil {
			klog.Errorf("parse flow entry error for bucket %d on emmu %d", index, emmu)
		}
	}()

	bucketBuffer := dev.getNfpBucketBuffer(emmu, uint32(index))

	if bucketBuffer[0] > 0 {
		flows := dev.getFlowEntryByBucketHash(emmu, uint32(index), true, filter)
		flowEntrys = append(flowEntrys, flows...)
	}

	if bucketBuffer[1] > 0 {
		entryIndex := (bucketBuffer[13] >> 8) & 0xFFFFFF
		if entryIndex > 0 && entryIndex != 0x1fffff {
			flows := dev.getFlowEntryByBucketHash(emmu, entryIndex, false, filter)
			flowEntrys = append(flowEntrys, flows...)
		}
	}

	if bucketBuffer[2] > 0 {
		entryIndex := (bucketBuffer[13] << 16) & 0xFF0000
		entryIndex = entryIndex | (bucketBuffer[14] >> 16)
		if entryIndex > 0 && entryIndex != 0x1fffff {
			flows := dev.getFlowEntryByBucketHash(emmu, entryIndex, false, filter)
			flowEntrys = append(flowEntrys, flows...)
		}
	}

	if bucketBuffer[3] > 0 {
		entryIndex := (bucketBuffer[14] << 8) & 0xFFFF00
		entryIndex = entryIndex | (bucketBuffer[15] >> 24)
		if entryIndex > 0 && entryIndex != 0x1fffff {
			flows := dev.getFlowEntryByBucketHash(emmu, entryIndex, false, filter)
			flowEntrys = append(flowEntrys, flows...)
		}
	}

	entryIndex := bucketBuffer[15] & 0xFFFFFF
	if entryIndex > 0 && entryIndex != 0x1fffff {
		flows := dev.getFlowEntryByBucketHash(emmu, entryIndex, false, filter)
		flowEntrys = append(flowEntrys, flows...)
	}

	return flowEntrys
}

func (dev *NfpDevice) prepareNfpFlowBuffer() error {
	var emuNum uint32

	ctmIsland := 32

	bucketSymName := C.CString("_FC_WC_EMU_0_BUCKETS_BASE")
	defer C.free(unsafe.Pointer(bucketSymName))

	dev.bucketSym = C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), bucketSymName)
	if dev.bucketSym == nil {
		util.LogFatalAndExit(nil, "Can not find _FC_WC_EMU_0_BUCKETS_BASE sym")
	}

	entrySymName := C.CString("_FC_WC_EMU_0_ENTRIES_BASE")
	defer C.free(unsafe.Pointer(entrySymName))
	dev.entrySym = C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), entrySymName)
	if dev.entrySym == nil {
		util.LogFatalAndExit(nil, "Can not find _FC_WC_EMU_0_ENTRIES_BASE sym")
	}

	fcMaskName := C.CString("i32._FC_WC_MASK_TABLE_BASE")
	defer C.free(unsafe.Pointer(fcMaskName))
	dev.fcMaskSym = C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), fcMaskName)
	if dev.fcMaskSym == nil {
		util.LogFatalAndExit(nil, "Can not find i32._FC_WC_MASK_TABLE_BASE sym")
	}

	payloadSymName := C.CString("_FC_WC_EMU_0_PAYLOADS_BASE")
	defer C.free(unsafe.Pointer(payloadSymName))
	dev.payloadSym = C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), payloadSymName)
	if dev.payloadSym == nil {
		util.LogFatalAndExit(nil, "Can not find _FC_WC_EMU_0_PAYLOADS_BASE sym")
	}

	emu2Name := C.CString("_FC_WC_EMU_2_BUCKETS_BASE")
	defer C.free(unsafe.Pointer(emu2Name))
	sym := C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), emu2Name)
	if sym != nil {
		emuNum = 3
	} else {
		emu1Name := C.CString("_FC_WC_EMU_1_BUCKETS_BASE")
		defer C.free(unsafe.Pointer(emu1Name))
		sym := C.nfp_rtsym_lookup((*C.struct_nfp_device)(dev.devPtr), emu1Name)
		if sym != nil {
			emuNum = 2
		} else {
			emuNum = 1
		}
	}
	dev.emuNum = emuNum
	dev.fcMask = make([]uint32, dev.fcMaskSym.size/4)
	dev.bucketBuffer = make([]uint32, dev.bucketSym.size/4)
	dev.bucketValid = make([]bool, dev.bucketSym.size/NfpReadBufferSize)
	dev.entryBuffer = make([]uint32, dev.entrySym.size/4)
	dev.entryValid = make([]bool, dev.entrySym.size/NfpReadBufferSize)
	dev.payloadBuffer = make([]uint32, dev.payloadSym.size/4)
	dev.payloadValid = make([]bool, dev.payloadSym.size/NfpReadBufferSize)
	dev.devMapCache = make(map[uint32]string)
	C.nfp_ctm_read((*C.struct_nfp_device)(dev.devPtr), C.int(ctmIsland),
		(unsafe.Pointer)(&dev.fcMask[0]), (C.ulonglong)(dev.fcMaskSym.size),
		(C.ulonglong)(dev.fcMaskSym.addr))

	return nil
}

func statsFlowEntryBatch(ch chan []*FlowEntry, done chan map[string]uint32) {
	stats := make(map[string]uint32)
	for flows := range ch {
		for _, flow := range flows {
			stats[flow.key.devName] += 1
		}
	}

	done <- stats
}

func StatsFlowEntry() map[string]uint32 {
	var numPerTask int = 80000
	var wg sync.WaitGroup
	var devices []*NfpDevice
	var ch chan []*FlowEntry
	var done chan map[string]uint32

	ch = make(chan []*FlowEntry, 100)
	done = make(chan map[string]uint32)
	go statsFlowEntryBatch(ch, done)

	corigineNicDevices := GetCorigineNicDevice()
	devices = make([]*NfpDevice, len(corigineNicDevices))
	for index, pcidevice := range corigineNicDevices {
		devices[index] = NewNfpDevice(uint(index), pcidevice)
		devices[index].prepareNfpFlowBuffer()
		bucketNum := devices[index].GetBucketCount(0)

		count := numPerTask
		for i := 0; i < bucketNum; i += numPerTask {
			if i+numPerTask > bucketNum {
				count = bucketNum - i
			}
			wg.Add(1)
			go devices[index].getFlowEntryBatch(ch, &wg, 0, i, count, nil)
		}
	}

	wg.Wait()
	close(ch)
	for _, device := range devices {
		device.Close()
	}
	return <-done
}

func (dev *NfpDevice) getFlowEntryBatch(ch chan []*FlowEntry, wg *sync.WaitGroup, emu uint32,
	start int, num int, filter *FlowFilter) {
	for i := start; i < start+num; i++ {
		flows := dev.getFlowEntryByBucket(emu, i, filter)
		if flows != nil {
			ch <- flows
		}
	}
	wg.Done()
}

func displayFlowEntryBatch(device *NfpDevice, ch chan []*FlowEntry, done chan int) {
	var totalNum uint32

	for flows := range ch {
		for _, flow := range flows {
			fmt.Printf("=====================EntryNo:%d======================\n", totalNum)
			flow.PrintEntryInfo()
			fmt.Println()
			totalNum++
		}
	}
	fmt.Println()
	fmt.Println()
	fmt.Printf("Nic:%s total:%d\n", device.PciDevice, totalNum)

	done <- 1
}

func updateCRIRuntimePodName() {
	var err error
	var rs internalapi.RuntimeService
	var defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///var/run/dockershim.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}

	for _, endPoint := range defaultRuntimeEndpoints {
		rs, err = remote.NewRemoteRuntimeService(endPoint, 2*time.Second, nil)
		if err != nil {
			klog.Errorf("Connect using endpoint %q error:%v", endPoint, err)
			continue
		}
		break
	}
	if rs == nil {
		klog.Info("Can not connect the the docker runtime service")
		return
	}
	filter := &pb.ContainerFilter{State: &pb.ContainerStateValue{State: pb.ContainerState_CONTAINER_RUNNING}}
	r, err := rs.ListContainers(context.TODO(), filter)
	if err != nil {
		klog.Infof("List container fail:%v from CRI runtime service.", err)
		return
	}

	for _, c := range r {
		ifname := fmt.Sprintf("%s_h", c.PodSandboxId[0:12])
		repNametoPod[ifname] = c.Labels[types.KubernetesPodNamespaceLabel] +
			"/" + c.Labels[types.KubernetesPodNameLabel]
	}
}

func updateK8sPodName() {
	var cfg *rest.Config
	var kubeClient *kubernetes.Clientset
	var err error
	cfg, err = rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", "/etc/kubernetes/admin.conf")
	}

	if err != nil {
		return
	}

	cfg.QPS = 1000
	cfg.Burst = 2000
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	kubeClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return
	}
	pods, err := kubeClient.CoreV1().Pods("").List(context.TODO(),
		metav1.ListOptions{FieldSelector: fmt.Sprintf("spec.nodeName=%s", os.Getenv("NODE_NAME"))})
	if err != nil {
		return
	}
	for _, pod := range pods.Items {
		mac, ok := pod.Annotations["kubernetes.customized/fabric-mac"]
		if !ok {
			continue
		}
		devname := strings.Replace(mac, ":", "", -1)
		nodelink, err := netlink.LinkByName(devname)
		if err != nil {
			continue
		}
		if nodelink.Type() == "bond" {
			devs := util.GetBondSlave(devname)
			for _, dev := range devs {
				repNametoPod[dev] = pod.Namespace + "/" + pod.Name
			}
		} else {
			repNametoPod[devname] = pod.Namespace + "/" + pod.Name
		}
	}
}

func DisplayFlowEntry(filter *FlowFilter) {
	var numPerTask int = 80000

	if os.Getenv("CNI_VENDOR") == "FABRIC" {
		updateK8sPodName()
	} else {
		updateCRIRuntimePodName()
	}
	corigineNicDevices := GetCorigineNicDevice()
	for index, pcidevice := range corigineNicDevices {
		var wg sync.WaitGroup
		ch := make(chan []*FlowEntry, 100)
		done := make(chan int)
		device := NewNfpDevice(uint(index), pcidevice)
		device.prepareNfpFlowBuffer()
		bucketNum := device.GetBucketCount(0)

		go displayFlowEntryBatch(device, ch, done)
		count := numPerTask
		for i := 0; i < bucketNum; i += numPerTask {
			if i+numPerTask > bucketNum {
				count = bucketNum - i
			}
			wg.Add(1)
			go device.getFlowEntryBatch(ch, &wg, 0, i, count, filter)
		}
		wg.Wait()
		close(ch)
		<-done
		device.Close()
	}
}
