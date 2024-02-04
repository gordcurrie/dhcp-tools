package env

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

// GetCapturesPath determines the path to where packet captures
// should be stored and creates the directory if it does not already
// exist. Should be in $HOME/.dhcp-tools/captures
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

// CleanCaptures deletes all files in the passed directory
func CleanCaptures(path string) error {
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	for _, f := range dir {
		os.RemoveAll(filepath.Join(path, f.Name()))
	}

	return nil
}
