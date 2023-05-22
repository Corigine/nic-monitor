package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var rootCmd = &cobra.Command{
	Use:   "flow",
	Short: "flow",
	Long:  `flow tools for corigine nic`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		klog.Error(err)
		os.Exit(1)
	}
}
