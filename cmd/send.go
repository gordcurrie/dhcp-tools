/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"log"

	"github.com/gordcurrie/dhcp-tools/internal/gui"
	"github.com/gordcurrie/dhcp-tools/internal/packet"
	"github.com/spf13/cobra"
)

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "send dhcp command on selected interface",
	Long:  `send dhcp command on selected interface`,
	Run: func(cmd *cobra.Command, args []string) {
		send()
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sendCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sendCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func send() {
	file, err := gui.SelectFile()
	if err != nil {
		log.Fatalf("error: could not select file, err: %v", err)
	}

	iFace, err := gui.SelectInterface()
	if err != nil {
		log.Fatalf("error: could not select interface, err: %v", err)
	}

	err = packet.Send(iFace, file)
	if err != nil {
		log.Fatalf("error: could not send packet, err: %v\n", err)
	}

}
