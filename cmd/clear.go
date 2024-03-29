package cmd

import (
	"log"

	"github.com/gordcurrie/dhcp-tools/internal/env"
	"github.com/spf13/cobra"
)

// clearCmd represents the clear command
var clearCmd = &cobra.Command{
	Use:   "clear",
	Short: "removes any stored captures from the captures directory",
	Long:  "removes any stored captures from the captures directory",
	Run: func(cmd *cobra.Command, args []string) {
		clearCaptures()
	},
}

func init() {
	rootCmd.AddCommand(clearCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// clearCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// clearCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func clearCaptures() {
	path, err := env.GetCapturesPath()
	if err != nil {
		log.Fatalf("error, could not get captures path. err: %v", err)
	}

	err = env.CleanCaptures(path)
	if err != nil {
		log.Fatalf("error, could not get captures path. err: %v", err)
	}
}
