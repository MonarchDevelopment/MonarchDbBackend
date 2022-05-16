package security

import (
	"testing"
	"time"
)

var manager NonceManager

func TestInitNonceManager(t *testing.T) {
	manager.InitNonceManager()

	// Check that the manager is unlocked
	manager.NonceLock.Lock()
	manager.NonceLock.Unlock()

	// Wait a while for the polling thread to do its things
	time.Sleep(NONCE_POLL_TIME)

	// Check that the manager is unlocked
	manager.NonceLock.Lock()
	manager.NonceLock.Unlock()
}

func TestUseNonce(t *testing.T) {
	err := manager.UseNonce(123123)
	if err == nil {
		t.Fail()
	}
}

func TestGetNonce(t *testing.T) {
	for i := 0; i < MAXIMUM_NONCES; i++ {
		nonce, err := manager.GetNonce()
		if err != nil {
			t.Log(err)
			t.Fail()
		}

		err = manager.UseNonce(nonce)
		if err != nil {
			t.Log(err)
			t.Fail()
		}
	}

	// Assert that the max nonce count can be hit
	var terr error = nil
	for i := 0; i < 2*MAXIMUM_NONCES; i++ {
		_, err := manager.GetNonce()
		if err != nil {
			terr = err
			break
		}
	}

	if terr == nil {
		t.Log("Maximum nonce count was not met")
		t.Fail()
	}

	manager.NonceLock.Lock()
	size := manager.NonceRemovalQueue.Len()
	manager.NonceLock.Unlock()

	if size != MAXIMUM_NONCES {
		t.Log("The nonce removal queue should be full")
		t.Log(size)
		t.Fail()
	}

	// This test will literally take a minute bruh
	// Assert that the nonces get removed over time
	time.Sleep(61 * 1000 * time.Millisecond)

	manager.NonceLock.Lock()
	size = manager.NonceRemovalQueue.Len()
	manager.NonceLock.Unlock()

	if size != 0 {
		t.Log("There should be no nonces in the queue at this point")
		t.Log(size)
		t.Fail()
	}
}
