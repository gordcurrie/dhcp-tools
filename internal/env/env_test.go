package env_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/gordcurrie/dhcp-tools/internal/env"
	"github.com/stretchr/testify/assert"
)

func Test_CleanCaptures(t *testing.T) {
	tempDirPath := filepath.Join(".", "test_captures")
	createSampleCaptures(t, tempDirPath, 2)

	files, err := ioutil.ReadDir(tempDirPath)
	if err != nil {
		t.Fatalf("could not read temp dir, err: %v", err)
	}

	assert.Equal(t, 2, len(files)) // confirm temp files are there
	env.CleanCaptures(tempDirPath)

	files, err = ioutil.ReadDir(tempDirPath)
	if err != nil {
		t.Fatalf("could not read temp dir, err: %v", err)
	}
	assert.Equal(t, 0, len(files)) // confirm temp files are deleted
}

func createSampleCaptures(t *testing.T, path string, count int) {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		t.Fatalf("could not create temp dir, err: %v", err)
	}

	for i := 0; i < count; i++ {
		_, err = os.CreateTemp(path, "capture_*")
		if err != nil {
			t.Fatalf("could not create temp file, err: %v", err)
		}
	}

	t.Cleanup(func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("could not remote temp dir, err: %v", err)
		}
	})
}
