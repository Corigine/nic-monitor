package cmd

import (
	"github.com/corigine/nic-monitor/pkg/nfp"

	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:     "dump",
	Aliases: []string{"d"},
	Short:   "Dump corigine nic flow entrys",
	Run: func(cmd *cobra.Command, args []string) {
		nfp.DisplayFlowEntry(&filter)
	},
}

var filter nfp.FlowFilter

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.Flags().StringVar(&filter.SrcIp, "srcip", "", "Filter by src ip")
	dumpCmd.Flags().StringVar(&filter.DstIp, "dstip", "", "Filter by dst ip")
	dumpCmd.Flags().StringVar(&filter.DevName, "devname", "", "Filter by dev name")
	dumpCmd.Flags().Uint16VarP(&filter.L4SrcPort, "l4srcport", "", 0, "Filter by L4 src port")
	dumpCmd.Flags().Uint16VarP(&filter.L4DstPort, "l4dstport", "", 0, "Filter by L4 dst port")
}
