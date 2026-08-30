// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"log"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestEngineConcurrency stresses the Mutex locks
func TestEngineConcurrency(t *testing.T) {
	log.Println("Starting Edge Concurrency Test...")

	engine := NewEngine("/tmp/test-engine", &MockCallback{})
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			engine.SetExitNode("Node-1")
			engine.AcceptSubnet("192.168.1.0/24", "Node-1")
			engine.RemoveSubnet("192.168.1.0/24")
		}(i)
	}

	wg.Wait()
	log.Println("Edge Concurrency Test Passed: No deadlocks or panics detected.")
}
