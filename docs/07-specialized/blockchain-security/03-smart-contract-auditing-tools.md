# Chapter 3: Smart Contract Auditing Tools

Automated tools are essential for identifying low-hanging fruit and complex edge cases in smart contracts. They fall into several categories: static analysis, symbolic execution, and fuzzing.

## 3.1 Automated Static Analysis

### Slither
Slither is a Python-based static analysis framework by Trail of Bits. It runs quickly and detects a wide variety of common vulnerabilities (e.g., reentrancy, uninitialized state variables).

**Installation:**
```bash
pip3 install slither-analyzer
```

**Usage:**
```bash
# Run Slither on a specific file
slither contracts/MyContract.sol

# Run Slither on a Foundry/Hardhat project
slither .
```

### Mythril
Mythril is a security analysis tool by ConsenSys that uses symbolic execution, SMT solving, and taint analysis. It's excellent for finding complex paths that lead to vulnerabilities.

**Installation (Docker recommended):**
```bash
docker pull mythril/myth
```

**Usage:**
```bash
docker run -v $(pwd):/share mythril/myth analyze /share/MyContract.sol
```

## 3.2 Symbolic Execution

### Manticore
Manticore, also by Trail of Bits, is a symbolic execution tool for smart contracts and binaries. It mathematically explores all possible execution paths to prove properties or find counterexamples.

**Installation:**
```bash
pip3 install manticore
```

**Usage:**
Manticore is typically scripted in Python.
```python
from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()
user_account = m.create_account(balance=1000)
contract_account = m.solidity_create_contract("MyContract.sol", owner=user_account)

# Explore state space...
```

## 3.3 Property-Based Fuzzing

Fuzzing involves sending random, massive amounts of inputs to a smart contract to see if it violates specific defined properties or reverts unexpectedly.

### Echidna
Echidna is a powerful property-based fuzzer designed for Ethereum smart contracts. You write Solidity properties, and Echidna attempts to break them.

**Installation (Docker):**
```bash
docker pull trailofbits/echidna
```

**Usage:**
Create a property file (`Test.sol`):
```solidity
import "./MyContract.sol";

contract Test is MyContract {
    // Echidna properties start with 'echidna_'
    function echidna_balance_under_limit() public view returns (bool) {
        return balances[msg.sender] <= 10000;
    }
}
```
Run Echidna:
```bash
docker run -it -v $(pwd):/code trailofbits/echidna echidna-test /code/Test.sol --contract Test
```

### Foundry (Forge Fuzzing)
Foundry has built-in property-based fuzzing that is extremely fast.

**Usage:**
```solidity
function testFuzz_deposit(uint256 amount) public {
    // Bound the random input
    vm.assume(amount > 0 && amount < 1000 ether);
    
    bank.deposit{value: amount}();
    assertEq(bank.balances(address(this)), amount);
}
```
Run tests:
```bash
forge test
```
