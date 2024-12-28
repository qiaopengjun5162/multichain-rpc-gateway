package chaindispatcher

import (
	"context"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/chain/ethereum"
	"runtime/debug"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ethereum/go-ethereum/log"

	"github.com/qiaopengjun5162/multichain-rpc-gateway/chain"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/config"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/rpc/account"
	"github.com/qiaopengjun5162/multichain-rpc-gateway/rpc/common"
)

type CommonRequest interface {
	GetChain() string
}

type CommonReply = account.SupportChainsResponse

type ChainType = string

type ChainDispatcher struct {
	registry map[ChainType]chain.IChainAdaptor
}

func New(conf *config.Config) (*ChainDispatcher, error) {
	dispatcher := ChainDispatcher{
		registry: make(map[ChainType]chain.IChainAdaptor),
	}
	chainAdaptorFactoryMap := map[string]func(conf *config.Config) (chain.IChainAdaptor, error){
		ethereum.ChainName: ethereum.NewChainAdaptor,
		//cosmos.ChainName:   cosmos.NewChainAdaptor,
		//solana.ChainName:   solana.NewChainAdaptor,
		//tron.ChainName:     tron.NewChainAdaptor,
		//aptos.ChainName:    aptos.NewChainAdaptor,
		//sui.ChainName:      sui.NewSuiAdaptor,
		//ton.ChainName:      ton.NewChainAdaptor,
	}

	supportedChains := []string{
		ethereum.ChainName,
		//cosmos.ChainName,
		//solana.ChainName,
		//tron.ChainName,
		//sui.ChainName,
		//ton.ChainName,
		//aptos.ChainName,
	}

	for _, c := range conf.Chains {
		if factory, ok := chainAdaptorFactoryMap[c]; ok {
			adaptor, err := factory(conf)
			if err != nil {
				log.Crit("failed to setup chain", "chain", c, "error", err)
			}
			dispatcher.registry[c] = adaptor
		} else {
			log.Error("unsupported chain", "chain", c, "supportedChains", supportedChains)
		}
	}
	return &dispatcher, nil
}

func (d *ChainDispatcher) Interceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Error("panic error", "msg", e)
			log.Debug(string(debug.Stack()))
			err = status.Errorf(codes.Internal, "Panic err: %v", e)
		}
	}()

	pos := strings.LastIndex(info.FullMethod, "/")
	method := info.FullMethod[pos+1:]

	chainName := req.(CommonRequest).GetChain()
	log.Info(method, "chain", chainName, "req", req)

	resp, err = handler(ctx, req)
	log.Debug("Finish handling", "resp", resp, "err", err)
	return
}

// preHandler checks if the chain specified in the request is supported by the dispatcher.
//
// req: An interface expected to implement the CommonRequest interface, which provides
//
//	the GetChain method to retrieve the chain name.
//
// Returns:
//   - A pointer to a CommonReply if the chain is not supported, containing an error code,
//     a message indicating unsupported operation, and a support flag set to false.
//   - Nil if the chain is supported.
func (d *ChainDispatcher) preHandler(req interface{}) (resp *CommonReply) {
	chainName := req.(CommonRequest).GetChain()
	if _, ok := d.registry[chainName]; !ok {
		return &CommonReply{
			Code:    common.ReturnCode_ERROR,
			Msg:     config.UnsupportedOperation,
			Support: false,
		}
	}
	return nil
}

func (d *ChainDispatcher) GetSupportChains(_ context.Context, request *account.SupportChainsRequest) (*account.SupportChainsResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SupportChainsResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  config.UnsupportedOperation,
		}, nil
	}
	return d.registry[request.Chain].GetSupportChains(request)
}

// ConvertAddress converts an address from one chain to another.
//
// ctx: The context for the RPC call. This context is used to control timeouts, cancellation, and other
//
//	request-scoped values.
//
// request: The request containing the chain name and the address to be converted.
//
// Returns:
// - A pointer to a ConvertAddressResponse containing the converted address or an error.
// - An error if the conversion fails or the pre-handler returns an error.
func (d *ChainDispatcher) ConvertAddress(ctx context.Context, request *account.ConvertAddressRequest) (*account.ConvertAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ConvertAddressResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "covert address fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].ConvertAddress(request)
}

func (d *ChainDispatcher) ValidAddress(ctx context.Context, request *account.ValidAddressRequest) (*account.ValidAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ValidAddressResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "valid address error at pre handle",
		}, nil
	}
	return d.registry[request.Chain].ValidAddress(request)
}

// GetBlockByNumber retrieves a block by its number from the specified chain.
//
// ctx: The context for the RPC call.
// request: The request containing the chain name and block number.
//
// Returns:
// - A pointer to a BlockResponse containing the block data or an error.
// - An error if the block retrieval fails or the pre-handler returns an error.
func (d *ChainDispatcher) GetBlockByNumber(ctx context.Context, request *account.BlockNumberRequest) (*account.BlockResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block by number fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByNumber(request)
}

func (d *ChainDispatcher) GetBlockByHash(ctx context.Context, request *account.BlockHashRequest) (*account.BlockResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByHash(request)
}

func (d *ChainDispatcher) GetBlockHeaderByHash(ctx context.Context, request *account.BlockHeaderHashRequest) (*account.BlockHeaderResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockHeaderResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block header by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockHeaderByHash(request)
}

func (d *ChainDispatcher) GetBlockHeaderByNumber(ctx context.Context, request *account.BlockHeaderNumberRequest) (*account.BlockHeaderResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockHeaderResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block header by number fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockHeaderByNumber(request)
}

func (d *ChainDispatcher) GetBlockHeaderByRange(_ context.Context, request *account.BlockByRangeRequest) (*account.BlockByRangeResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockByRangeResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block range header fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByRange(request)
}

func (d *ChainDispatcher) GetAccount(ctx context.Context, request *account.AccountRequest) (*account.AccountResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.AccountResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get account information fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetAccount(request)
}

// GetFee retrieves the gas price from the specified chain.
//
// ctx: The context for the RPC call.
// request: The request containing the chain name.
//
// Returns:
// - A pointer to a FeeResponse containing the gas price or an error.
// - An error if the gas price retrieval fails or the pre-handler returns an error.
func (d *ChainDispatcher) GetFee(ctx context.Context, request *account.FeeRequest) (*account.FeeResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.FeeResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get fee fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetFee(request)
}

func (d *ChainDispatcher) SendTx(_ context.Context, request *account.SendTxRequest) (*account.SendTxResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SendTxResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "send tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].SendTx(request)
}

func (d *ChainDispatcher) GetTxByAddress(_ context.Context, request *account.TxAddressRequest) (*account.TxAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.TxAddressResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get tx by address fail pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetTxByAddress(request)
}

func (d *ChainDispatcher) GetTxByHash(ctx context.Context, request *account.TxHashRequest) (*account.TxHashResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.TxHashResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get tx by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetTxByHash(request)
}

func (d *ChainDispatcher) GetBlockByRange(ctx context.Context, request *account.BlockByRangeRequest) (*account.BlockByRangeResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockByRangeResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get block by range fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByRange(request)
}

func (d *ChainDispatcher) CreateUnSignTransaction(ctx context.Context, request *account.UnSignTransactionRequest) (*account.UnSignTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.UnSignTransactionResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get un sign tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].CreateUnSignTransaction(request)
}

func (d *ChainDispatcher) BuildSignedTransaction(_ context.Context, request *account.SignedTransactionRequest) (*account.SignedTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SignedTransactionResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "signed tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].BuildSignedTransaction(request)
}

func (d *ChainDispatcher) DecodeTransaction(ctx context.Context, request *account.DecodeTransactionRequest) (*account.DecodeTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.DecodeTransactionResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "decode tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].DecodeTransaction(request)
}

func (d *ChainDispatcher) VerifySignedTransaction(ctx context.Context, request *account.VerifyTransactionRequest) (*account.VerifyTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.VerifyTransactionResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "verify tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].VerifySignedTransaction(request)
}

func (d *ChainDispatcher) GetExtraData(ctx context.Context, request *account.ExtraDataRequest) (*account.ExtraDataResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ExtraDataResponse{
			Code: common.ReturnCode_ERROR,
			Msg:  "get extra data fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetExtraData(request)
}