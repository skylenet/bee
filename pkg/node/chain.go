package node

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/logging"
	"github.com/ethersphere/bee/pkg/p2p/libp2p"
	"github.com/ethersphere/bee/pkg/settlement/swap"
	"github.com/ethersphere/bee/pkg/settlement/swap/chequebook"
	"github.com/ethersphere/bee/pkg/settlement/swap/swapprotocol"
	"github.com/ethersphere/bee/pkg/settlement/swap/transaction"
	"github.com/ethersphere/bee/pkg/storage"
)

const (
	maxDelay = 1 * time.Minute
)

// InitChain will initialize the Ethereum backend at the given endpoint and
// set up the Transacton Service to interact with it using the provided signer.
func InitChain(
	p2pctx context.Context,
	log logging.Logger,
	endpoint string,
	signer crypto.Signer,
) (
	backend *ethclient.Client,
	overlayEthAddress common.Address,
	chainID int64,
	transactionService transaction.Service,
	err error,
) {
	backend, err = ethclient.Dial(endpoint)
	if err != nil {
		err = fmt.Errorf("failed to connect to the Ethereum backend at %s: %w", endpoint, err)
		return
	}

	transactionService, err = transaction.NewService(log, backend, signer)
	if err != nil {
		err = fmt.Errorf("failed to init transaction service: %w", err)
		return
	}

	overlayEthAddress, err = signer.EthereumAddress()
	if err != nil {
		err = fmt.Errorf("failed to determine overlay Ethereum address: %w", err)
		return
	}

	cID, err := backend.ChainID(p2pctx)
	if err != nil {
		log.Infof(
			"could not connect to backend at %s. With swap enabled on the",
			" network a working blockchain node (for goerli network in",
			" production) is required. Check your node or specify another node",
			" endpont using --swap-endpoint",
			endpoint,
		)
		err = fmt.Errorf("could not get chain ID from endpoint %s: %w", endpoint, err)
		return
	}
	chainID = cID.Int64()

	return
}

// InitChequebook will initialize everything needed to operate the chequebook:
// the chequebook factory and service, as well as the cheque store and cashout
// service.
func InitChequebook(
	p2pctx context.Context,
	log logging.Logger,
	stateStore storage.StateStorer,
	overlayEthAddress common.Address,
	chainID int64,
	signer crypto.Signer,
	transactionService transaction.Service,
	swapBackend *ethclient.Client,
	swapFactoryAddress string,
	swapInitialDeposit string,
) (
	chequebookService chequebook.Service,
	chequeStore chequebook.ChequeStore,
	cashoutService chequebook.CashoutService,
	err error,
) {
	var factoryAddress common.Address
	if swapFactoryAddress != "" {
		if !common.IsHexAddress(swapFactoryAddress) {
			err = fmt.Errorf("malformed swap factory address %s", swapFactoryAddress)
			return
		}
		factoryAddress = common.HexToAddress(swapFactoryAddress)
		log.Infof("using custom swap factory address: %x", factoryAddress)
	} else {
		addr, found := chequebook.DiscoverFactoryAddress(chainID)
		if !found {
			err = errors.New("no known factory address for this network")
			return
		}
		log.Infof("using default factory address for chain id %d: %x", chainID, addr)
		factoryAddress = addr
	}

	chequebookFactory, err := chequebook.NewFactory(
		swapBackend,
		transactionService,
		factoryAddress,
		chequebook.NewSimpleSwapFactoryBindingFunc,
	)
	if err != nil {
		err = fmt.Errorf("failed to init chequebook factory: %w", err)
		return
	}

	chequeSigner := chequebook.NewChequeSigner(signer, chainID)

	isSynced, err := transaction.IsSynced(p2pctx, swapBackend, maxDelay)
	if err != nil {
		err = fmt.Errorf("failed to sync with the Ethereum chain: %w", err)
		return
	}
	if !isSynced {
		log.Infof("waiting to sync with the Ethereum backend")
		err = transaction.WaitSynced(p2pctx, swapBackend, maxDelay)
		if err != nil {
			err = fmt.Errorf("could not wait to sync with the Ethereum chain: %w", err)
			return
		}
	}

	deposit, ok := new(big.Int).SetString(swapInitialDeposit, 10)
	if !ok {
		err = fmt.Errorf("invalid intial swap deposit: %w", err)
		return
	}

	chequebookService, err = chequebook.Init(
		p2pctx,
		chequebookFactory,
		stateStore,
		log,
		deposit,
		transactionService,
		swapBackend,
		chainID,
		overlayEthAddress,
		chequeSigner,
		chequebook.NewSimpleSwapBindings,
		chequebook.NewERC20Bindings,
	)
	if err != nil {
		err = fmt.Errorf("failed to init chequebook service: %w", err)
		return
	}

	chequeStore = chequebook.NewChequeStore(
		stateStore,
		swapBackend,
		chequebookFactory,
		chainID,
		overlayEthAddress,
		chequebook.NewSimpleSwapBindings,
		chequebook.RecoverCheque,
	)

	cashoutService, err = chequebook.NewCashoutService(
		stateStore,
		chequebook.NewSimpleSwapBindings,
		swapBackend,
		transactionService,
		chequeStore,
	)
	if err != nil {
		err = fmt.Errorf("failed to init cashout service: %w", err)
		return
	}

	return
}

// InitSwap will intialize and register the swap service.
func InitSwap(
	p2ps *libp2p.Service,
	log logging.Logger,
	stateStore storage.StateStorer,
	networkID uint64,
	overlayEthAddress common.Address,
	chequebookService chequebook.Service,
	chequeStore chequebook.ChequeStore,
	cashoutService chequebook.CashoutService,
) (swapService *swap.Service, err error) {
	swapProtocol := swapprotocol.New(p2ps, log, overlayEthAddress)
	swapAddressBook := swap.NewAddressbook(stateStore)

	swapService = swap.New(
		swapProtocol,
		log,
		stateStore,
		chequebookService,
		chequeStore,
		swapAddressBook,
		networkID,
		cashoutService,
		p2ps,
	)

	swapProtocol.SetSwap(swapService)

	err = p2ps.AddProtocol(swapProtocol.Protocol())
	if err != nil {
		err = fmt.Errorf("failed to add swap protocol: %w", err)
	}

	return
}
