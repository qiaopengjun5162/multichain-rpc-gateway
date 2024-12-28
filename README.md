# multichain-rpc-gateway

**multichain-rpc-gateway** is an account model chains RPC service gateway that supports multiple blockchain networks such as **Ethereum**, **Aptos**, **Cosmos**, **Sui**, **Solana**, and others. This project is written in **Go** and provides a **gRPC** interface for upper-layer services to interact with these blockchains.

## Features

- **Multi-Chain Support**: Currently supports Ethereum, Aptos, Cosmos, Sui, Solana, and potentially more.
- **Go Implementation**: Written in Go for performance and scalability.
- **gRPC Interface**: Provides a flexible gRPC interface to interact with the blockchain networks.
- **Account Model**: Focused on blockchain account management and service gateway functionality.

## Installation

### Prerequisites

To build and run **multichain-rpc-gateway**, you need:

- Go 1.18 or later.
- A Go environment set up on your local machine.

### Clone the Repository

```bash
git clone https://github.com/<username>/multichain-rpc-gateway.git
cd multichain-rpc-gateway
```

### Build the Project

To build the project, run the following command:

```bash
go build -o multichain-rpc-gateway .
```

### Run the Gateway

To start the service, execute:

```bash
./multichain-rpc-gateway
```

## Usage

The `multichain-rpc-gateway` exposes a gRPC interface for upper-layer services to access. You can define the specific blockchain network and account model to interact with. Example usage can be found in the `/examples` directory.

### Example gRPC Service

1. Define your service using `.proto` files.
2. Generate the Go code for gRPC using `protoc`:

```bash
protoc --go_out=plugins=grpc:. your_service.proto
```

3. Implement the service methods and interact with the multichain-rpc-gateway.

## Supported Blockchains

Currently, **multichain-rpc-gateway** supports the following blockchain networks:

- **Ethereum**
- **Aptos**
- **Cosmos**
- **Sui**
- **Solana**

Support for additional blockchains can be added by contributing to the project.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Contributing

We welcome contributions to **multichain-rpc-gateway**! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Open a pull request to the main repository.

Please ensure that your code follows the existing style and passes the tests.

## Contact

For questions or support, open an issue or contact us directly.

## Acknowledgements

- **Go** for building this service.
- **gRPC** for providing a robust interface for communication between services.
- **The blockchain communities** for their continuous development and innovations.
