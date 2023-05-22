package cmd

import (
	"fmt"
	"time"

	"github.com/corigine/nic-monitor/pkg/nfp"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:     "stats",
	Aliases: []string{"s"},
	Short:   "Statistic corigine nic flow entrys by devname",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(time.Now())
		var total uint32
		result := nfp.StatsFlowEntry()
		fmt.Printf("%-16s %s\n", "Name", "Counter")
		fmt.Println("========================================")
		for devname, count := range result {
			fmt.Printf("%-16s %d\n", devname, count)
			total += count
		}
		fmt.Println("========================================")
		fmt.Printf("%-16s %d\n", "total", total)
		fmt.Println(time.Now())
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
