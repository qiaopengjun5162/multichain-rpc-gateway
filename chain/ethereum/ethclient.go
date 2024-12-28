package ethereum

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/qiaopengjun5162/multichain-rpc-gateway/common/global_const"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/common/helpers"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/common/retry"
)

const (
	defaultDialTimeout    = 5 * time.Second
	defaultDialAttempts   = 5
	defaultRequestTimeout = 10 * time.Second
)

type TransactionList struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Hash  string `json:"hash"`
	Value string `json:"value"`
}

type RpcBlock struct {
	Hash         common.Hash       `json:"hash"`
	Height       uint64            `json:"height"`
	Transactions []TransactionList `json:"transactions"`
	BaseFee      string            `json:"baseFeePerGas"`
}

type EthClient interface {
	BlockHeaderByNumber(*big.Int) (*types.Header, error)
	BlockByNumber(*big.Int) (*RpcBlock, error)
	BlockByHash(common.Hash) (*RpcBlock, error)
	LatestSafeBlockHeader() (*types.Header, error)
	LatestFinalizedBlockHeader() (*types.Header, error)
	BlockHeaderByHash(common.Hash) (*types.Header, error)
	BlockHeadersByRange(*big.Int, *big.Int, uint) ([]types.Header, error)

	TxByHash(common.Hash) (*types.Transaction, error)
	TxReceiptByHash(common.Hash) (*types.Receipt, error)

	StorageHash(common.Address, *big.Int) (common.Hash, error)
	FilterLogs(filterQuery ethereum.FilterQuery, chainId uint) (Logs, error)

	TxCountByAddress(common.Address) (hexutil.Uint64, error)

	SendRawTransaction(rawTx string) (*common.Hash, error)

	SuggestGasPrice() (*big.Int, error)
	SuggestGasTipCap() (*big.Int, error)

	EthGetCode(common.Address) (string, error)

	GetBalance(address common.Address) (*big.Int, error)

	Close()
}

type client struct {
	rpc RPC
}

// DialEthClient connects to the given JSON-RPC URL and returns an EthClient
// instance. The context is used to set a timeout for the dial operation.
//
// The returned EthClient is safe for concurrent use by multiple goroutines.
//
// The function will retry the dial operation several times if it fails,
// with exponential backoff between attempts. If all attempts fail, the
// function returns an error.
func DialEthClient(ctx context.Context, rpcUrl string) (EthClient, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDialTimeout)
	defer cancel()

	bOff := retry.Exponential()
	rpcClient, err := retry.Do(ctx, defaultDialAttempts, bOff, func() (*rpc.Client, error) {
		if !helpers.IsURLAvailable(rpcUrl) {
			return nil, fmt.Errorf("address unavailable (%s)", rpcUrl)
		}

		client, err := rpc.DialContext(ctx, rpcUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to dial address (%s): %w", rpcUrl, err)
		}

		return client, nil
	})

	if err != nil {
		return nil, err
	}

	return &client{rpc: NewRPC(rpcClient)}, nil
}

func (c *client) BlockHeaderByHash(hash common.Hash) (*types.Header, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var header *types.Header
	err := c.rpc.CallContext(ctxt, &header, "eth_getBlockByHash", hash, false)
	if err != nil {
		return nil, err
	} else if header == nil {
		return nil, ethereum.NotFound
	}

	if header.Hash() != hash {
		return nil, errors.New("header mismatch")
	}

	return header, nil
}

func (c *client) LatestSafeBlockHeader() (*types.Header, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var header *types.Header
	err := c.rpc.CallContext(ctxt, &header, "eth_getBlockByNumber", "safe", false)
	if err != nil {
		return nil, err
	} else if header == nil {
		return nil, ethereum.NotFound
	}

	return header, nil
}

func (c *client) LatestFinalizedBlockHeader() (*types.Header, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var header *types.Header
	err := c.rpc.CallContext(ctxt, &header, "eth_getBlockByNumber", "finalized", false)
	if err != nil {
		return nil, err
	} else if header == nil {
		return nil, ethereum.NotFound
	}

	return header, nil
}

// BlockByNumber retrieves the Ethereum block by block number.
//
// Parameters:
// - number: A pointer to a big.Int representing the block number.
//
// Returns:
// - A pointer to a RpcBlock representing the Ethereum block.
// - An error if the retrieval fails.
//
// The function uses a context with a timeout of defaultRequestTimeout to call the "eth_getBlockByNumber" method.
// If the call fails, it logs the error and returns nil along with the error.
// If the call succeeds but the block is nil, it logs a warning and returns nil along with ethereum.NotFound.
// Otherwise, it returns the block and nil.
func (c *client) BlockByNumber(number *big.Int) (*RpcBlock, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	var block *RpcBlock
	err := c.rpc.CallContext(ctxt, &block, "eth_getBlockByNumber", toBlockNumArg(number), true)
	if err != nil {
		log.Error("Call eth_getBlockByNumber method fail", "err", err)
		return nil, err
	} else if block == nil {
		log.Warn("header not found")
		return nil, ethereum.NotFound
	}
	return block, nil
}

func (c *client) BlockByHash(hash common.Hash) (*RpcBlock, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	var block *RpcBlock
	err := c.rpc.CallContext(ctxt, &block, "eth_getBlockByHash", hash, true)
	if err != nil {
		log.Error("Call eth_getBlockByHash method fail", "err", err)
		return nil, err
	} else if block == nil {
		log.Warn("header not found")
		return nil, ethereum.NotFound
	}
	return block, nil
}

func (c *client) TxCountByAddress(address common.Address) (hexutil.Uint64, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	var nonce hexutil.Uint64
	err := c.rpc.CallContext(ctxt, &nonce, "eth_getTransactionCount", address, "latest")
	if err != nil {
		log.Error("Call eth_getTransactionCount method fail", "err", err)
		return 0, err
	}
	log.Info("get nonce by address success", "nonce", nonce)
	return nonce, err
}

func (c *client) SuggestGasPrice() (*big.Int, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	var hex hexutil.Big
	if err := c.rpc.CallContext(ctxt, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

func (c *client) SuggestGasTipCap() (*big.Int, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	var hex hexutil.Big
	if err := c.rpc.CallContext(ctxt, &hex, "eth_maxPriorityFeePerGas"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

func (c *client) SendRawTransaction(rawTx string) (*common.Hash, error) {
	var txHash common.Hash
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()
	if err := c.rpc.CallContext(ctxt, &txHash, "eth_sendRawTransaction", rawTx); err != nil {
		return nil, err
	}
	log.Info("send tx to ethereum success", "txHash", txHash.Hex())
	return &txHash, nil
}

// BlockHeaderByNumber retrieves the Ethereum block header for the specified block number.
//
// Parameters:
// - number: A pointer to a big.Int representing the block number.
//
// Returns:
// - A pointer to a types.Header representing the Ethereum block header.
// - An error if the retrieval fails.
//
// The function uses a context with a timeout of defaultRequestTimeout to call the "eth_getBlockByNumber" method.
// If the call fails, it logs the error and returns nil along with the error.
// If the call succeeds but the header is nil, it logs a warning and returns nil along with ethereum.NotFound.
// Otherwise, it returns the header and nil.
func (c *client) BlockHeaderByNumber(number *big.Int) (*types.Header, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var header *types.Header
	err := c.rpc.CallContext(ctxt, &header, "eth_getBlockByNumber", toBlockNumArg(number), false)
	if err != nil {
		log.Error("Call eth_getBlockByNumber method fail", "err", err)
		return nil, err
	} else if header == nil {
		log.Warn("header not found")
		return nil, ethereum.NotFound
	}

	return header, nil
}

func (c *client) BlockHeadersByRange(startHeight, endHeight *big.Int, chainId uint) ([]types.Header, error) {
	if startHeight.Cmp(endHeight) == 0 {
		header, err := c.BlockHeaderByNumber(startHeight)
		if err != nil {
			return nil, err
		}
		return []types.Header{*header}, nil
	}

	count := new(big.Int).Sub(endHeight, startHeight).Uint64() + 1
	headers := make([]types.Header, count)
	batchElems := make([]rpc.BatchElem, count)
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	if chainId == uint(global_const.ZkFairSepoliaChainId) ||
		chainId == uint(global_const.ZkFairChainId) {
		groupSize := 100
		var wg sync.WaitGroup
		numGroups := (int(count)-1)/groupSize + 1
		wg.Add(numGroups)

		for i := 0; i < int(count); i += groupSize {
			start := i
			end := i + groupSize - 1
			if end > int(count) {
				end = int(count) - 1
			}
			go func(start, end int) {
				defer wg.Done()
				for j := start; j <= end; j++ {
					height := new(big.Int).Add(startHeight, new(big.Int).SetUint64(uint64(j)))
					batchElems[j] = rpc.BatchElem{
						Method: "eth_getBlockByNumber",
						Result: new(types.Header),
						Error:  nil,
					}
					header := new(types.Header)
					batchElems[j].Error = c.rpc.CallContext(ctxt, header, batchElems[j].Method, toBlockNumArg(height), false)
					batchElems[j].Result = header
				}
			}(start, end)
		}

		wg.Wait()
	} else {
		for i := uint64(0); i < count; i++ {
			height := new(big.Int).Add(startHeight, new(big.Int).SetUint64(i))
			batchElems[i] = rpc.BatchElem{Method: "eth_getBlockByNumber", Args: []interface{}{toBlockNumArg(height), false}, Result: &headers[i]}
		}
		err := c.rpc.BatchCallContext(ctxt, batchElems)
		if err != nil {
			return nil, err
		}
	}
	size := 0
	for i, batchElem := range batchElems {
		header, ok := batchElem.Result.(*types.Header)
		if !ok {
			return nil, fmt.Errorf("unable to transform rpc response %v into types.Header", batchElem.Result)
		}
		headers[i] = *header
		size = size + 1
	}
	headers = headers[:size]

	return headers, nil
}

// TxByHash retrieves the Ethereum transaction for the specified transaction hash.
//
// Parameters:
// - hash: A common.Hash representing the transaction hash.
//
// Returns:
// - A pointer to a types.Transaction representing the Ethereum transaction.
// - An error if the retrieval fails.
//
// The function uses a context with a timeout of defaultRequestTimeout to call the "eth_getTransactionByHash" method.
// If the call fails, it returns nil along with the error.
// If the call succeeds but the transaction is nil, it returns nil along with ethereum.NotFound.
// Otherwise, it returns the transaction and nil.
func (c *client) TxByHash(hash common.Hash) (*types.Transaction, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var tx *types.Transaction
	err := c.rpc.CallContext(ctxt, &tx, "eth_getTransactionByHash", hash)
	if err != nil {
		return nil, err
	} else if tx == nil {
		return nil, ethereum.NotFound
	}

	return tx, nil
}

func (c *client) TxReceiptByHash(hash common.Hash) (*types.Receipt, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var txReceipt *types.Receipt
	err := c.rpc.CallContext(ctxt, &txReceipt, "eth_getTransactionReceipt", hash)
	if err != nil {
		return nil, err
	} else if txReceipt == nil {
		return nil, ethereum.NotFound
	}

	return txReceipt, nil
}

func (c *client) StorageHash(address common.Address, blockNumber *big.Int) (common.Hash, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	proof := struct{ StorageHash common.Hash }{}
	err := c.rpc.CallContext(ctxt, &proof, "eth_getProof", address, nil, toBlockNumArg(blockNumber))
	if err != nil {
		return common.Hash{}, err
	}

	return proof.StorageHash, nil
}

func (c *client) EthGetCode(account common.Address) (string, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var result hexutil.Bytes
	err := c.rpc.CallContext(ctxt, &result, "eth_getCode", account)
	if err != nil {
		return "", err
	}
	if result.String() == "0x" {
		return "eoa", nil
	} else {
		return "contract", nil
	}
}

func (c *client) GetBalance(address common.Address) (*big.Int, error) {
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var result hexutil.Big
	err := c.rpc.CallContext(ctxt, &result, "eth_getBalance", address, "latest")
	if err != nil {
		return nil, fmt.Errorf("get balance failed: %w", err)
	}

	balance := (*big.Int)(&result)
	return balance, nil
}

func (c *client) Close() {
	c.rpc.Close()
}

type Logs struct {
	Logs          []types.Log
	ToBlockHeader *types.Header
}

func (c *client) FilterLogs(query ethereum.FilterQuery, chainId uint) (Logs, error) {
	arg, err := toFilterArg(query)
	if err != nil {
		return Logs{}, err
	}

	var logs []types.Log
	var header types.Header

	batchElems := make([]rpc.BatchElem, 2)
	batchElems[0] = rpc.BatchElem{Method: "eth_getBlockByNumber", Args: []interface{}{toBlockNumArg(query.ToBlock), false}, Result: &header}
	batchElems[1] = rpc.BatchElem{Method: "eth_getLogs", Args: []interface{}{arg}, Result: &logs}
	ctxt, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout*10)
	defer cancel()
	if chainId == uint(global_const.ZkFairSepoliaChainId) ||
		chainId == uint(global_const.ZkFairChainId) {

		batchElems[0].Error = c.rpc.CallContext(ctxt, &header, batchElems[0].Method, toBlockNumArg(query.ToBlock), false)
		batchElems[1].Error = c.rpc.CallContext(ctxt, &logs, batchElems[1].Method, arg)
	} else {
		err = c.rpc.BatchCallContext(ctxt, batchElems)
		if err != nil {
			return Logs{}, err
		}
	}

	if batchElems[0].Error != nil {
		return Logs{}, fmt.Errorf("unable to query for the `FilterQuery#ToBlock` header: %w", batchElems[0].Error)
	}
	if batchElems[1].Error != nil {
		return Logs{}, fmt.Errorf("unable to query logs: %w", batchElems[1].Error)
	}
	return Logs{Logs: logs, ToBlockHeader: &header}, nil
}

type RPC interface {
	Close()
	CallContext(ctx context.Context, result any, method string, args ...any) error
	BatchCallContext(ctx context.Context, b []rpc.BatchElem) error
}

type rpcClient struct {
	rpc *rpc.Client
}

func NewRPC(client *rpc.Client) RPC {
	return &rpcClient{client}
}

// Close closes the RPC client.
//
// It is safe to call Close multiple times. Subsequent calls will be no-ops.
func (c *rpcClient) Close() {
	c.rpc.Close()
}

func (c *rpcClient) CallContext(ctx context.Context, result any, method string, args ...any) error {
	err := c.rpc.CallContext(ctx, result, method, args...)
	return err
}

func (c *rpcClient) BatchCallContext(ctx context.Context, b []rpc.BatchElem) error {
	err := c.rpc.BatchCallContext(ctx, b)
	return err
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	return rpc.BlockNumber(number.Int64()).String()
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{"address": q.Addresses, "topics": q.Topics}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, errors.New("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}
