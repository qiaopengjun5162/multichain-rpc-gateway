package ethereum

import (
	"encoding/hex"
	"math/big"

	"github.com/pkg/errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// BuildErc20Data constructs the data payload for an ERC-20 token transfer using the
// `transfer(address,uint256)` function signature.
//
// Parameters:
// - toAddress: The recipient's Ethereum address, represented as a *common.Address.
// - amount: The amount of tokens to transfer, represented as a *big.Int.
//
// Returns:
// A byte slice representing the constructed data payload.
func BuildErc20Data(toAddress common.Address, amount *big.Int) []byte {
	var data []byte

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := crypto.Keccak256Hash(transferFnSignature)
	methodId := hash[:5]
	dataAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	dataAmount := common.LeftPadBytes(amount.Bytes(), 32)

	data = append(data, methodId...)
	data = append(data, dataAddress...)
	data = append(data, dataAmount...)

	return data
}

// BuildErc721Data constructs the data payload for an ERC-721 token transfer using the
// `safeTransferFrom` function signature. It prepares the data by encoding the method
// identifier and padding the `fromAddress`, `toAddress`, and `tokenId` to 32 bytes.
//
// Parameters:
// - fromAddress: The Ethereum address from which the token is being transferred.
// - toAddress: The Ethereum address to which the token is being transferred.
// - tokenId: The unique identifier of the ERC-721 token being transferred.
//
// Returns:
// A byte slice containing the encoded data payload ready for inclusion in a transaction.
func BuildErc721Data(fromAddress, toAddress common.Address, tokenId *big.Int) []byte {
	var data []byte

	transferFnSignature := []byte("safeTransferFrom(address,address,uint256)")
	hash := crypto.Keccak256Hash(transferFnSignature)
	methodId := hash[:5]

	dataFromAddress := common.LeftPadBytes(fromAddress.Bytes(), 32)
	dataToAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	dataTokenId := common.LeftPadBytes(tokenId.Bytes(), 32)

	data = append(data, methodId...)
	data = append(data, dataFromAddress...)
	data = append(data, dataToAddress...)
	data = append(data, dataTokenId...)

	return data
}

// CreateLegacyUnSignTx creates an unsigned transaction for the given txData and chainId.
// It returns the transaction hash as a string.
//
// Parameters:
// - txData: The transaction data, represented as a *types.LegacyTx.
// - chainId: The chain ID of the Ethereum network, represented as a *big.Int.
//
// Returns:
// A string containing the transaction hash.
func CreateLegacyUnSignTx(txData *types.LegacyTx, chainId *big.Int) string {
	tx := types.NewTx(txData)
	signer := types.LatestSignerForChainID(chainId)
	txHash := signer.Hash(tx)
	return txHash.String()
}

// CreateEip1559UnSignTx creates an unsigned transaction for the given txData and chainId.
// It returns the transaction hash as a string, or an error if the transaction creation fails.
//
// Parameters:
// - txData: The transaction data, represented as a *types.DynamicFeeTx.
// - chainId: The chain ID of the Ethereum network, represented as a *big.Int.
//
// Returns:
// A string containing the transaction hash, or an error.
func CreateEip1559UnSignTx(txData *types.DynamicFeeTx, chainId *big.Int) (string, error) {
	tx := types.NewTx(txData)
	// 签名者
	signer := types.LatestSignerForChainID(chainId)
	txHash := signer.Hash(tx)
	return txHash.String(), nil
}

// CreateEip1559SignedTx creates a signed transaction for the given txData and chainId.
// It uses the provided signature to sign the transaction and encodes it to RLP format.
//
// Parameters:
// - txData: The transaction data, represented as a *types.DynamicFeeTx.
// - signature: The signature to be used for signing the transaction, represented as a byte slice.
// - chainId: The chain ID of the Ethereum network, represented as a *big.Int.
//
// Returns:
// A tuple containing:
// - The signer used to sign the transaction.
// - The signed transaction, represented as a *types.Transaction.
// - The encoded signed transaction in hexadecimal format, stripped of the "0x" prefix.
// - The transaction hash.
// - An error, if the signing or encoding process fails.
func CreateEip1559SignedTx(txData *types.DynamicFeeTx, signature []byte, chainId *big.Int) (types.Signer, *types.Transaction, string, string, error) {
	tx := types.NewTx(txData)
	signer := types.LatestSignerForChainID(chainId)
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return nil, nil, "", "", errors.New("tx with signature fail")
	}
	signedTxData, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return nil, nil, "", "", errors.New("encode tx to byte fail")
	}
	return signer, signedTx, "0x" + hex.EncodeToString(signedTxData)[4:], signedTx.Hash().String(), nil
}

// CreateLegacySignedTx creates a signed transaction for the given legacy transaction data and chain ID.
// It uses the provided signature to sign the transaction and encodes it to RLP format.
//
// Parameters:
// - txData: The transaction data, represented as a *types.LegacyTx.
// - signature: The signature to be used for signing the transaction, represented as a byte slice.
// - chainId: The chain ID of the Ethereum network, represented as a *big.Int.
//
// Returns:
// A tuple containing:
// - A string representing the encoded signed transaction in hexadecimal format.
// - A string containing the transaction hash.
// - An error, if the signing or encoding process fails.
func CreateLegacySignedTx(txData *types.LegacyTx, signature []byte, chainId *big.Int) (string, string, error) {
	tx := types.NewTx(txData)
	signer := types.LatestSignerForChainID(chainId)
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return "", "", errors.New("tx with signature fail")
	}
	signedTxData, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return "", "", errors.New("encode tx to byte fail")
	}
	return "0x" + hex.EncodeToString(signedTxData), signedTx.Hash().String(), nil
}
