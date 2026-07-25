# Chapter 1: Introduction to Blockchain & Smart Contract Security

## 1.1 Blockchain Architecture & the EVM
A blockchain is a decentralized, distributed ledger maintained by a network of nodes. Ethereum introduced the concept of a Turing-complete state machine known as the **Ethereum Virtual Machine (EVM)**.

### The Ethereum Virtual Machine (EVM)
The EVM is a sandboxed, isolated runtime environment where smart contracts execute. Every node in the Ethereum network runs the EVM and executes exactly the same instructions to maintain consensus on the global state.

- **Storage:** Persistent, expensive data storage on the blockchain.
- **Memory:** Temporary, cheaper data storage cleared between external function calls.
- **Stack:** Used to hold small local variables; EVM is a stack-based machine.

### Gas Mechanism
To prevent infinite loops and allocate network resources fairly, Ethereum uses **Gas**. Every EVM opcode costs a specific amount of gas. If a transaction runs out of gas, it is reverted, but the gas consumed is still paid to the block validators (miners/stakers).

## 1.2 Smart Contract Lifecycle
The lifecycle of a smart contract includes:
1. **Development:** Writing code in Solidity or Vyper.
2. **Compilation:** Compiling code into EVM bytecode and an Application Binary Interface (ABI).
3. **Deployment:** Sending a transaction with the bytecode to the empty address `0x0`. This creates the contract and assigns it an address.
4. **Execution:** Users (or other contracts) interact with the contract by sending transactions to its address.
5. **Immutability:** Once deployed, the code cannot be changed. Upgradability requires complex proxy patterns.

## 1.3 The Web3 Threat Landscape
In traditional AppSec, a bug might leak PII or lead to unauthorized access. In Web3, a bug often leads directly to the theft of millions of dollars.

### Key Differences from Traditional AppSec:
- **Public by Default:** Contract bytecode is public. State variables, even if marked `private`, are visible on the blockchain.
- **Immutability:** You cannot simply patch a live contract. You must deploy a new one or use proxy patterns.
- **Financial Exigency:** Smart contracts often handle highly liquid assets (ETH, ERC20 tokens), making them prime targets.
- **Composability (DeFi Legos):** Contracts interact with other contracts seamlessly. A vulnerability in one contract can cascade through the ecosystem (e.g., flash loan attacks).

## 1.4 Decentralized Finance (DeFi) Threat Vectors
DeFi protocols are subject to unique economic and technical threats:
- **Flash Loans:** Uncollateralized loans that must be repaid within the same transaction. Attackers use flash loans to temporarily acquire massive capital to manipulate markets and exploit logic flaws.
- **Oracle Manipulation:** Manipulating off-chain data feeds (e.g., token prices) to trick a smart contract into making incorrect financial calculations.
- **Front-running/MEV (Maximal Extractable Value):** Attackers and validators observe pending transactions in the mempool and reorder them or insert their own to extract profit (e.g., sandwich attacks).
