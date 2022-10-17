# Spearbit Writing Exercise

## Wallet Protocol Business Requirments

You are given an implementation for a smart contract wallet. There are two contracts

1. [`Implementation.sol`](contracts/Implementation.sol): Deployed once and used as implementation contract in `Proxy.sol`.
2. [`Proxy.sol`](contracts/Proxy.sol): Each user has a unique `Proxy` deployment with the above implementation. This is a simply proxy contract which delegatecalls the implementation contract. It has an access control check that allows only the owner to use the fallback function.

The idea is that users can keep their funds, for example, ETH or ERC20 tokens in the Proxy. To use these funds, users can execute arbitrary calls and arbitrary delegatecalls by using the implementation contract (it has `callContract` and `delegatecallContract`). The implementation contract is deployed only once and reused to save gas.

There is a **critical bug** in the wallet protocol. The exercise is to find it and write it in markdown format, in accordance with the style guide.

## Implementation deletion causes DoS of the user proxy contract

**Severity:** Critical

**Context:** [Implementation.sol#L9-L22](https://github.com/shabarkin/writing-exercise/blob/develop/src/Implementation.sol#L9-L22)

**Impact:** 
An attacker could delete the implementation contract deployed for user proxy contracts. All users funds deposited to their proxy contracts could be stuck forever without any option to withdraw.

**Recommendation:**
Change the context of `Implementation` smart contract from contract to library. Update their functions by removing the `payable` 
modifier.
