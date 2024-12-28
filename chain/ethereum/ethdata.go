package ethereum

import (
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/dapplink-labs/chain-explorer-api/common/account"
	"github.com/dapplink-labs/chain-explorer-api/common/chain"
	"github.com/dapplink-labs/chain-explorer-api/explorer/etherscan"
)

type EthData struct {
	EthDataCli *etherscan.ChainExplorerAdaptor
}

// NewEthDataClient creates a new EthereumScan client based on the given API key,
// base URL, and timeout duration.
//
// Parameters:
// - baseUrl: The base URL of the EthereumScan API.
// - apiKey: The API key used to authenticate the API requests.
// - timeout: The timeout duration for the API requests.
//
// Returns:
// - A pointer to an EthData instance, which encapsulates the EthereumScan client.
// - An error if the EthereumScan client cannot be created.
func NewEthDataClient(baseUrl, apiKey string, timeout time.Duration) (*EthData, error) {
	ethereumScanCli, err := etherscan.NewChainExplorerAdaptor(apiKey, baseUrl, false, time.Duration(timeout))
	if err != nil {
		log.Error("New ethereumScan client fail", "err", err)
		return nil, err
	}
	return &EthData{EthDataCli: ethereumScanCli}, err
}

// GetTxByAddress retrieves the Ethereum transaction records for the specified
// address and action type, given the page number and page size.
//
// Parameters:
// - page: The page number of the result set.
// - pageSize: The number of records per page.
// - address: The Ethereum address for which to retrieve the transaction records.
// - action: The type of action to filter the transactions by.
//
// Returns:
// - A pointer to a TransactionResponse containing the transaction records.
// - An error if the retrieval fails.
func (ed *EthData) GetTxByAddress(page, pageSize uint64, address string, action account.ActionType) (*account.TransactionResponse[account.AccountTxResponse], error) {
	request := &account.AccountTxRequest{
		PageRequest: chain.PageRequest{
			Page:  page,
			Limit: pageSize,
		},
		Action:  action,
		Address: address,
	}
	txData, err := ed.EthDataCli.GetTxByAddress(request)
	if err != nil {
		return nil, err
	}
	return txData, nil
}

// GetBalanceByAddress retrieves the balance for a specific Ethereum address and contract.
//
// Parameters:
// - contractAddr: The contract address to filter the balance query.
// - address: The Ethereum address for which to retrieve the balance.
//
// Returns:
// - A pointer to an AccountBalanceResponse containing the balance details.
// - An error if the retrieval fails.
func (ed *EthData) GetBalanceByAddress(contractAddr, address string) (*account.AccountBalanceResponse, error) {
	accountItem := []string{address}
	symbol := []string{"ETH"}
	contractAddress := []string{contractAddr}
	protocolType := []string{""}
	page := []string{"1"}
	limit := []string{"10"}
	accountBalanceReq := &account.AccountBalanceRequest{
		ChainShortName:  "ETH",
		ExplorerName:    "etherescan",
		Account:         accountItem,
		Symbol:          symbol,
		ContractAddress: contractAddress,
		ProtocolType:    protocolType,
		Page:            page,
		Limit:           limit,
	}
	ethereumScanResp, err := ed.EthDataCli.GetAccountBalance(accountBalanceReq)
	if err != nil {
		log.Error("get account balance error", "err", err)
		return nil, err
	}
	return ethereumScanResp, nil
}
