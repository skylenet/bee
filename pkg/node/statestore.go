package node

import (
	"fmt"
	"path/filepath"

	"github.com/ethersphere/bee/pkg/logging"
	"github.com/ethersphere/bee/pkg/statestore/leveldb"
	"github.com/ethersphere/bee/pkg/statestore/mock"
	"github.com/ethersphere/bee/pkg/storage"
)

// InitStateStore will initialze the stateStore with the given data directory.
func InitStateStore(log logging.Logger, dataDir string) (ret storage.StateStorer, err error) {
	if dataDir == "" {
		ret = mock.NewStateStore()
		log.Warning("using in-mem state store, no node state will be persisted")
		return ret, nil
	}
	ret, err = leveldb.NewStateStore(filepath.Join(dataDir, "statestore"), log)
	if err != nil {
		return nil, fmt.Errorf("statestore: %w", err)
	}
	return ret, nil
}
