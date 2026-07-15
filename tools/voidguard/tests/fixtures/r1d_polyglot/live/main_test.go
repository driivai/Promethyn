package main

import (
	"os"
	"testing"
)

func TestNeedsCluster(t *testing.T) {
	if os.Getenv("CLUSTER_FLAG") == "" {
		t.Skip("set CLUSTER_FLAG to run")
	}
}
