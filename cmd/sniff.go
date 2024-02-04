package cmd

import (
	"log"

	"github.com/gordcurrie/dhcp-tools/internal/gui"
	"github.com/gordcurrie/dhcp-tools/internal/packet"
	"github.com/spf13/cobra"
)

// sniffCmd represents the sniff command
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "sniffs DHCP traffic",
	Long:  `Sniffs local traffic filtering out dhcp packets and displaying them`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sniffDhcp(args)
	},
}

func init() {
	rootCmd.AddCommand(sniffCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sniffCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	sniffCmd.Flags().BoolVarP(&capture, "capture", "c", false, "outputs data to passed file")
}

func sniffDhcp(args []string) {
	iface, err := gui.SelectInterface()
	if err != nil {
		log.Fatalf("error: could not select interface, err: %v\n", err)
	}

	err = packet.Sniff(iface, capture)
	if err != nil {
		log.Fatalf("error: could not sniff packets, err: %v\n", err)
	}
}
