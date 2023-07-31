package nicmonitor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

var KubeClient *kubernetes.Clientset

// Configuration contains parameters information.
type Configuration struct {
	ListenPort      int
	PullInterval    int
	MonitorInterval int
	StasInterval    int
	MetricsPath     string
	KubeConfigFile  string
}

// ParseFlags get parameters information.
func ParseFlags() (*Configuration, error) {
	var (
		argListenPort      = pflag.Int("listen-port", 10770, "Tcp port to listen on for web interface and telemetry.")
		argMetricsPath     = pflag.String("telemetry-path", "/metrics", "Path under which to expose metrics.")
		argPullInterval    = pflag.Int("interval", 30, "The minimum interval (in seconds) between collections.")
		argStatInterval    = pflag.Int("stat-interval", 15, "The minimum interval (in seconds) between collections.")
		argMonitorInterval = pflag.Int("keepalive-interval", 3, "The minimum interval (in seconds) between collections.")
		argKubeConfigFile  = pflag.String("kubeconfig", "", "Path to kubeconfig file with authorization and master location information. If not set use the inCluster token.")
	)

	pflag.Parse()

	config := &Configuration{
		ListenPort:      *argListenPort,
		MetricsPath:     *argMetricsPath,
		PullInterval:    *argPullInterval,
		StasInterval:    *argStatInterval,
		MonitorInterval: *argMonitorInterval,
		KubeConfigFile:  *argKubeConfigFile,
	}

	err := config.initK8sApiServerClient()
	if err != nil {
		klog.Errorf("Init k8s Api Server fail %v", err)
	}
	klog.Infof("nic monitor config is %+v", config)
	return config, nil
}

func (config *Configuration) initK8sApiServerClient() (err error) {
	var cfg *rest.Config

	if config.KubeConfigFile == "" {
		klog.Infof("no --kubeconfig, use in-cluster kubernetes config")
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", config.KubeConfigFile)
	}
	if err != nil {
		return
	}
	cfg.QPS = 1000
	cfg.Burst = 2000
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	KubeClient = kubeClient

	//wait k8s-cluster ready
	for true {
		pods, err := kubeClient.CoreV1().Pods("").List(context.TODO(),
			metav1.ListOptions{FieldSelector: fmt.Sprintf("spec.nodeName=%s", os.Getenv("NODE_NAME"))})
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		for _, pod := range pods.Items {
			var retryCount int32
			mac, ok := pod.Annotations["kubernetes.customized/fabric-mac"]
			if !ok {
				continue
			}
			devname := strings.Replace(mac, ":", "", -1)
			for true {
				_, err = netlink.LinkByName(devname)
				if err != nil {
					if retryCount > 20 {
						klog.Errorf("Get dev %s fail", devname)
						break
					}
					time.Sleep(5 * time.Second)
					retryCount++
					continue
				}
				break
			}
		}

		return err
	}

	return
}
