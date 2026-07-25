# Chapter 5: Web3 Bridge & Oracle Security

Beyond smart contract code, systemic risks in Web3 exist at the architecture layer, specifically concerning cross-chain communication and off-chain data feeds.

## 5.1 Cross-Chain Bridge Security
Bridges allow assets to move between different blockchains (e.g., Ethereum to Solana). They are prime targets for hackers due to the massive liquidity locked inside them (e.g., Ronin, Wormhole hacks).

### How Bridges Work (Lock and Mint)
1. User locks Token A in a smart contract on Chain A.
2. An off-chain relayer (or set of validators) observes this event.
3. The relayer instructs a smart contract on Chain B to mint Token B (a wrapped version of Token A).

### Bridge Threat Vectors
- **Validator Compromise:** If the off-chain relayers are centralized or use weak multisig, attackers can steal private keys and authorize fraudulent mints.
- **False Deposit Events:** Exploiting smart contract bugs to emit "Deposit" events without actually locking funds.
- **Message Forgery:** Faking cryptographic proofs so the destination chain believes a legitimate transaction occurred on the source chain.

## 5.2 Flash Loan Attacks
Flash loans allow users to borrow massive amounts of capital without collateral, provided the loan is returned within the exact same block.

### The Attack Mechanics
Attackers use flash loans to artificially manipulate the price of an asset within a single transaction block. 
1. Borrow millions in stablecoins.
2. Dump stablecoins on an illiquid decentralized exchange (DEX), crashing the target token's price.
3. Trigger a liquidation or exploit a protocol that relies on that DEX for price data.
4. Repay the flash loan and keep the profit.

## 5.3 Oracle Security (Chainlink & Pyth)
Smart contracts cannot make API calls to the outside world. They rely on **Oracles** to bring off-chain data (like asset prices or weather data) on-chain.

### The Vulnerability: Centralized/Manipulable Oracles
If a DeFi protocol uses a single DEX (like Uniswap) as its price oracle, it is highly susceptible to flash loan manipulation. The contract queries the DEX pool balance to determine the price, which the attacker has temporarily skewed.

### Secure Integration: Decentralized Oracle Networks (DONs)
**Chainlink:**
Chainlink aggregates price data from multiple independent node operators and multiple data sources.
```solidity
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SecureDeFi {
    AggregatorV3Interface internal priceFeed;

    constructor() {
        // ETH/USD price feed address
        priceFeed = AggregatorV3Interface(0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419);
    }

    function getLatestPrice() public view returns (int) {
        (
            /* uint80 roundID */,
            int price,
            /* uint startedAt */,
            /* uint timeStamp */,
            /* uint80 answeredInRound */
        ) = priceFeed.latestRoundData();
        return price;
    }
}
```

**Pyth Network:**
Pyth provides low-latency price feeds directly from first-party data providers (exchanges, trading firms).
It often uses a "pull" model where users publish the price update on-chain as part of their transaction, ensuring data freshness.
