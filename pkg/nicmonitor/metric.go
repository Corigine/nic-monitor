package nicmonitor

import "github.com/prometheus/client_golang/prometheus"

const metricNamespace = "corigine_nic"

var (
	metricNicTemperature = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "temperature",
			Help:      "corigine nic temperature, the unit is celsius",
		},
		[]string{
			"hostname",
			"pci",
		})

	metricNicLatancy = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "latancy",
			Help:      "the latancy of nic, the unit is us",
		},
		[]string{
			"hostname",
			"pci",
		})
	metricNicFlowNum = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "flow_num",
			Help:      "the num of flow for the sriov pod which used corigine nic.",
		},
		[]string{
			"namespace",
			"pod",
			"pci",
		})

	metricNicRxByte = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "rxByte",
			Help:      "the number of packet bytes.",
		},
		[]string{
			"namespace",
			"pod",
		})

	metricNicRxPkt = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "rxPkt",
			Help:      "the number of packet bytes.",
		},
		[]string{
			"namespace",
			"pod",
		})

	metricNicTxByte = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "txByte",
			Help:      "the number of packet bytes.",
		},
		[]string{
			"namespace",
			"pod",
		})

	metricNicTxPkt = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "txPkt",
			Help:      "the number of packet.",
		},
		[]string{
			"namespace",
			"pod",
		})
	metricNicTxDropPkt = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "txDropPkt",
			Help:      "the number of err packet.",
		},
		[]string{
			"namespace",
			"pod",
		})
	metricNicRxDropPkt = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "rxDropPkt",
			Help:      "the number of err packet.",
		},
		[]string{
			"namespace",
			"pod",
		})

	metricNicStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "status",
			Help:      "the status of nic.",
		},
		[]string{
			"hostname",
			"pci",
		})
)

func registerNicMetrics() {
	prometheus.MustRegister(metricNicTemperature)
	prometheus.MustRegister(metricNicLatancy)
	prometheus.MustRegister(metricNicFlowNum)
	prometheus.MustRegister(metricNicRxByte)
	prometheus.MustRegister(metricNicRxPkt)
	prometheus.MustRegister(metricNicTxByte)
	prometheus.MustRegister(metricNicTxPkt)
	prometheus.MustRegister(metricNicRxDropPkt)
	prometheus.MustRegister(metricNicTxDropPkt)
	prometheus.MustRegister(metricNicStatus)
}
