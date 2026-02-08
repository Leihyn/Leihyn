# SENTINEL PoC Templates

Ready-to-use exploit proof-of-concept templates for smart contract security research.

## Structure

```
poc/
├── protocols/          # EVM Protocol-specific templates
│   ├── aave_v3_poc.sol
│   ├── uniswap_v3_poc.sol
│   ├── curve_poc.sol
│   ├── balancer_poc.sol
│   ├── lido_poc.sol
│   ├── gmx_poc.sol
│   └── compound_v3_poc.sol
├── solana/             # Solana/Anchor templates
│   └── anchor_poc.rs
├── move/               # Move (Aptos/Sui) templates
│   └── aptos_poc.move
└── cairo/              # Cairo (Starknet) templates
    └── starknet_poc.cairo
```

## EVM Protocol Templates

### Aave V3 (`aave_v3_poc.sol`)
- Health factor manipulation
- Flash loan attacks
- eMode switching exploits
- Self-liquidation scenarios

### Uniswap V3 (`uniswap_v3_poc.sol`)
- slot0 price manipulation (CRITICAL)
- TWAP vs spot price analysis
- Callback reentrancy
- Tick math edge cases

### Curve (`curve_poc.sol`)
- Read-only reentrancy via `get_virtual_price()`
- Vyper reentrancy bug (0.2.15-0.3.0)
- Imbalanced pool exploitation
- Vulnerable vs safe lending examples

### Balancer (`balancer_poc.sol`)
- Rate provider read-only reentrancy
- Zero-fee flash loan amplification
- BPT price manipulation
- VaultReentrancyLib protection patterns

### Lido (`lido_poc.sol`)
- Rebasing balance caching vulnerabilities
- Share vs balance confusion
- Transfer amount mismatch
- wstETH vs stETH differences
- Negative rebase (slashing) handling

### GMX (`gmx_poc.sol`)
- Price impact manipulation
- Funding rate exploitation
- Oracle latency arbitrage
- Keeper MEV extraction
- ADL (auto-deleverage) victimization

### Compound V3 (`compound_v3_poc.sol`)
- Absorption (liquidation) manipulation
- Interest rate manipulation
- Supply cap exploitation
- Oracle staleness attacks

## Non-EVM Templates

### Solana/Anchor (`anchor_poc.rs`)
- Missing signer checks
- Account confusion / type cosplay
- PDA seed manipulation
- Missing owner checks
- Integer overflow
- Reinitialization attacks
- Closing accounts incorrectly

### Move/Aptos (`aptos_poc.move`)
- Missing signer validation
- Unauthorized resource access
- Arithmetic overflow
- Capability leaks
- Reinitialization
- Flash loan pattern issues
- Time manipulation

### Cairo/Starknet (`starknet_poc.cairo`)
- Missing caller validation
- Felt252 overflow
- Reentrancy
- L1-L2 message vulnerabilities
- Signature malleability
- Initialization issues

## Usage

### Foundry (EVM)
```bash
# Clone template
cp templates/poc/protocols/aave_v3_poc.sol test/exploits/

# Run exploit test
forge test --match-contract AaveHealthFactorManipulation -vvvv

# Fork mainnet
forge test --fork-url $ETH_RPC_URL --match-test test_healthFactorManipulation
```

### Anchor (Solana)
```bash
# Add to tests directory
cp templates/poc/solana/anchor_poc.rs programs/my-program/tests/

# Run tests
anchor test
```

### Move (Aptos)
```bash
# Add to sources
cp templates/poc/move/aptos_poc.move sources/

# Run tests
aptos move test
```

### Cairo (Starknet)
```bash
# Add to src
cp templates/poc/cairo/starknet_poc.cairo src/

# Run tests
scarb test
```

## Template Features

Each template includes:

1. **Common Interfaces** - Protocol-specific interfaces ready to use
2. **Mainnet Addresses** - Real deployed contract addresses
3. **Attack Examples** - Working exploit demonstrations
4. **Vulnerable vs Safe** - Side-by-side comparison patterns
5. **Test Structure** - Foundry/framework test setup
6. **Documentation** - Inline comments explaining vulnerabilities

## Contributing

When adding new templates:

1. Follow existing naming conventions
2. Include both vulnerable and safe examples
3. Add real mainnet addresses where applicable
4. Document attack vectors clearly
5. Include working test cases
