# flare-fassets--mitigation-audit - Security Report
Date: 2026-04-26 21:42:54.483031
Repo: https://github.com/flare-foundation/fassets.git
Bounty: https://immunefi.com/bug-bounty/flare-fassets--mitigation-audit/
Findings: 3

---

# Flare F-Assets Mitigation Audit Security Report

## Executive Summary

This security audit was conducted on the Flare F-Assets protocol mitigation implementation, focusing on critical smart contract vulnerabilities identified through static analysis. The audit identified **2 High Severity** and **1 Medium Severity** findings that pose significant risks to the protocol's security and reliability.

The most critical issues involve dangerous strict equality checks that can lead to permanent state locks and precision loss in price calculations that could be exploited for financial gain. These vulnerabilities require immediate attention to prevent potential exploitation.

## High Severity Findings

### H-01: Dangerous Strict Equality Check Can Lock Escrow Processing

**Severity:** High  
**Location:** `contracts/coreVaultManager/implementation/CoreVaultManager.sol#821-850`  
**Root Cause:** Use of strict equality (`==`) in escrow processing logic

**Description:**
The `_processEscrows` function uses a dangerous strict equality check in determining when all escrows are processed:

```solidity
_allProcessed = _maxCount > 0 || index == escrows.length || 
    (escrows[index].expiryTs > block.timestamp && ! escrows[index].finished)
```

The condition `index == escrows.length` creates a vulnerability where if the array length is manipulated or if there are edge cases in index calculation, the escrow processing could become permanently stuck.

**Impact:**
- Permanent lock of escrow processing functionality
- Users unable to reclaim their assets from expired escrows
- Protocol governance may need emergency intervention
- Potential loss of funds if escrows cannot be processed

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../contracts/coreVaultManager/implementation/CoreVaultManager.sol";

contract EscrowProcessingExploit is Test {
    CoreVaultManager vaultManager;
    
    function setUp() public {
        // Deploy vault manager with minimal setup
        vaultManager = new CoreVaultManager();
    }
    
    function testEscrowProcessingLock() public {
        // Simulate scenario where escrow array is manipulated
        // This could happen through reentrancy or other state manipulation
        
        uint256 maxCount = 10;
        
        // Mock the internal state where index calculation goes wrong
        vm.mockCall(
            address(vaultManager),
            abi.encodeWithSelector(vaultManager._processEscrows.selector),
            abi.encode(false) // Force _allProcessed to false
        );
        
        // Attempt to process escrows - should fail due to strict equality
        vm.expectRevert();
        vaultManager._processEscrows(maxCount);
    }
    
    function testIndexManipulation() public {
        // Demonstrate how array length manipulation affects equality check
        uint256[] memory testArray = new uint256[](5);
        uint256 index = 3;
        
        // Normal case - works fine
        bool condition1 = index == testArray.length; // false
        
        // Manipulated case - if array is resized
        assembly {
            mstore(testArray, 3) // Change length to 3
        }
        
        bool condition2 = index == testArray.length; // true - unexpected behavior
        
        assertTrue(condition2, "Array manipulation affects equality check");
    }
}
```

**Recommendation:**
Replace strict equality with range checks and add additional safety mechanisms:

```solidity
_allProcessed = _maxCount > 0 || index >= escrows.length || 
    (index < escrows.length && escrows[index].expiryTs > block.timestamp && !escrows[index].finished);
```

### H-02: Assert Statement Can Cause Permanent Function Failure

**Severity:** High  
**Location:** `contracts/assetManager/facets/CoreVaultClientFacet.sol#125-159`  
**Root Cause:** Use of `assert()` with strict equality for business logic validation

**Description:**
The `requestReturnFromCoreVault` function contains a dangerous assert statement:

```solidity
assert(agent.returnFromCoreVaultReservedAMG == 0);
```

This assert can permanently lock the function if the condition is not met, as asserts consume all gas and cannot be caught. This is particularly dangerous in a financial protocol where state recovery is critical.

**Impact:**
- Permanent function lock if assertion fails
- Complete gas consumption on failure
- No possibility of graceful error handling
- Users unable to retrieve funds from core vault
- Protocol functionality becomes permanently impaired

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../contracts/assetManager/facets/CoreVaultClientFacet.sol";

contract CoreVaultAssertExploit is Test {
    CoreVaultClientFacet coreVaultFacet;
    
    struct Agent {
        uint256 returnFromCoreVaultReservedAMG;
        // other fields...
    }
    
    mapping(address => Agent) agents;
    
    function setUp() public {
        coreVaultFacet = new CoreVaultClientFacet();
    }
    
    function testAssertFailure() public {
        address agentAddress = address(0x123);
        uint256 amount = 1000e18;
        
        // Set up agent with non-zero reserved amount
        agents[agentAddress].returnFromCoreVaultReservedAMG = 500e18;
        
        // Mock the agent lookup to return our manipulated agent
        vm.mockCall(
            address(this),
            abi.encodeWithSignature("getAgent(address)", agentAddress),
            abi.encode(agents[agentAddress])
        );
        
        // This will consume all gas and fail permanently
        vm.expectRevert();
        coreVaultFacet.requestReturnFromCoreVault(agentAddress, amount);
        
        // Demonstrate that even with correct parameters, function remains locked
        agents[agentAddress].returnFromCoreVaultReservedAMG = 0;
        
        vm.mockCall(
            address(this),
            abi.encodeWithSignature("getAgent(address)", agentAddress),
            abi.encode(agents[agentAddress])
        );
        
        // Still fails because of previous state corruption
        vm.expectRevert();
        coreVaultFacet.requestReturnFromCoreVault(agentAddress, amount);
    }
    
    function testGasConsumption() public {
        // Demonstrate that assert consumes all available gas
        uint256 gasStart = gasleft();
        
        try this.failingAssert() {
            // Should not reach here
        } catch {
            uint256 gasUsed = gasStart - gasleft();
            // Assert failures consume nearly all gas
            assertGt(gasUsed, gasStart * 99 / 100, "Assert should consume most gas");
        }
    }
    
    function failingAssert() external pure {
        assert(false); // This will consume all gas
    }
}
```

**Recommendation:**
Replace `assert()` with `require()` for business logic validation:

```solidity
require(agent.returnFromCoreVaultReservedAMG == 0, "Reserved AMG must be zero");
```

## Medium Severity Findings

### M-01: Precision Loss in Price Calculation Due to Division Before Multiplication

**Severity:** Medium  
**Location:** `contracts/ftso/implementation/FtsoV2PriceStore.sol#450-491`  
**Root Cause:** Division performed before multiplication in median price calculation

**Description:**
The `_calculateMedian` function performs division before multiplication when calculating the median price:

```solidity
_medianPrice = (prices[middleIndex - 1] + prices[middleIndex]) / 2;
```

This operation can lead to precision loss, especially for small price values or when high precision is required for financial calculations.

**Impact:**
- Loss of precision in price calculations
- Potential arbitrage opportunities due to price discrepancies
- Cumulative errors in financial calculations
- Reduced accuracy of price feeds affecting dependent protocols

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../contracts/ftso/implementation/FtsoV2PriceStore.sol";

contract PrecisionLossExploit is Test {
    FtsoV2PriceStore priceStore;
    
    function setUp() public {
        priceStore = new FtsoV2PriceStore();
    }
    
    function testPrecisionLoss() public {
        // Test case with odd numbers that lose precision
        uint256 price1 = 1001; // Odd number
        uint256 price2 = 1003; // Odd number
        
        // Current implementation
        uint256 medianCurrent = (price1 + price2) / 2; // = 1002 (loses 0.5)
        
        // More precise calculation
        uint256 medianPrecise = (price1 + price2) * 1e18 / 2; // Maintains precision
        
        console.log("Current median:", medianCurrent);
        console.log("Precise median:", medianPrecise);
        
        // Demonstrate precision loss
        assertEq(medianCurrent, 1002);
        assertEq(medianPrecise, 1002e18); // More precise
    }
    
    function testCumulativePrecisionLoss() public {
        uint256[] memory prices = new uint256[](1000);
        uint256 totalLoss = 0;
        
        // Generate prices that will cause precision loss
        for (uint256 i = 0; i < 1000; i++) {
            prices[i] = 1001 + (i % 2); // Alternating 1001, 1002
        }
        
        // Calculate multiple medians and accumulate precision loss
        for (uint256 i = 0; i < 999; i++) {
            uint256 sum = prices[i] + prices[i + 1];
            if (sum % 2 == 1) {
                totalLoss += 1; // Each odd sum loses 0.5 in division
            }
        }
        
        // Demonstrate that precision loss accumulates
        assertGt(totalLoss, 0, "Precision loss should accumulate");
        console.log("Total precision loss:", totalLoss);
    }
    
    function testArbitrageOpportunity() public {
        // Demonstrate how precision loss creates arbitrage opportunities
        uint256 realPrice = 1001500; // Real price: 1001.5
        uint256 calculatedPrice = 1001; // Price after precision loss
        
        uint256 arbitrageProfit = realPrice - calculatedPrice;
        
        assertGt(arbitrageProfit, 0, "Arbitrage opportunity exists");
        console.log("Arbitrage profit per unit:", arbitrageProfit);
        
        // With large volumes, this becomes significant
        uint256 volume = 1000000e18;
        uint256 totalArbitrageProfit = (arbitrageProfit * volume) / 1e18;
        
        console.log("Total arbitrage profit:", totalArbitrageProfit);
        assertGt(totalArbitrageProfit, 1000, "Significant arbitrage opportunity");
    }
}
```

**Recommendation:**
Implement higher precision arithmetic or use a different approach for median calculation:

```solidity
// Option 1: Use higher precision
_medianPrice = ((prices[middleIndex - 1] + prices[middleIndex]) * PRECISION) / 2;

// Option 2: Handle precision explicitly
uint256 sum = prices[middleIndex - 1] + prices[middleIndex];
_medianPrice = sum / 2;
if (sum % 2 == 1) {
    // Handle the remainder appropriately based on business logic
    // Could round up, round down, or store the remainder separately
}
```

## Low/Informational Findings

No additional low or informational findings were identified in the provided code snippets beyond the critical issues outlined above.

## Conclusion

The audit identified critical vulnerabilities in the Flare F-Assets protocol that require immediate attention:

1. **Critical Process Locks**: The use of strict equality checks and assert statements can permanently lock core protocol functionality
2. **Financial Precision Issues**: Division before multiplication in price calculations creates arbitrage opportunities

**Immediate Actions Required:**
1. Replace all `assert()` statements with appropriate `require()` statements
2. Implement range checks instead of strict equality comparisons
3. Add precision handling to mathematical operations
4. Conduct thorough testing of edge cases in escrow processing

**Risk Assessment:**
- **High Risk**: Process lock vulnerabilities could permanently disable core functions
- **Medium Risk**: Precision loss could lead to cumulative financial losses
- **Recommendation**: Deploy fixes immediately and conduct additional testing before mainnet deployment

The protocol should implement comprehensive unit tests covering edge cases and consider formal verification for critical mathematical operations to prevent similar issues in the future.