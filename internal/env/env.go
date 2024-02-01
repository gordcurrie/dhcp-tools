package env

import (
	"os"
	"path/filepath"
)

func GetCapturesPath() (string, error) {
	var homeDir string
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" {
		homeDir = filepath.Join("/home", sudoUser)
	} else {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	newpath := filepath.Join(homeDir, ".dhcp-tools", "captures")
	err := os.MkdirAll(newpath, os.ModePerm)
	if err != nil {
		return "", err
	}

	return newpath, nil
}
