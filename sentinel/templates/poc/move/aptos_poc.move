/// Move (Aptos) Exploit PoC Template
/// Common attack vectors for Aptos Move modules
///
/// COMMON VULNERABILITIES:
/// 1. Missing signer validation
/// 2. Unauthorized resource access
/// 3. Arithmetic overflow/underflow
/// 4. Capability leaks
/// 5. Reentrancy via callbacks
/// 6. Flash loan abuse
/// 7. Oracle manipulation

module exploit_poc::vulnerabilities {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::account;
    use aptos_framework::timestamp;

    // =========================================================================
    // ERROR CODES
    // =========================================================================
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;
    const E_ALREADY_INITIALIZED: u64 = 3;
    const E_OVERFLOW: u64 = 4;

    // =========================================================================
    // DATA STRUCTURES
    // =========================================================================

    struct Vault has key {
        balance: Coin<AptosCoin>,
        admin: address,
    }

    struct UserBalance has key {
        amount: u64,
        last_update: u64,
    }

    struct AdminCapability has key, store {
        admin: address,
    }

    // =========================================================================
    // VULNERABILITY 1: Missing Signer Validation
    // =========================================================================

    /// VULNERABLE: No signer check on admin operations
    public entry fun vulnerable_set_admin(
        _account: &signer,  // BUG: signer not validated!
        new_admin: address,
    ) acquires Vault {
        // Anyone can call this and change admin
        let vault = borrow_global_mut<Vault>(@exploit_poc);
        vault.admin = new_admin;
    }

    /// SAFE: Proper signer validation
    public entry fun safe_set_admin(
        account: &signer,
        new_admin: address,
    ) acquires Vault {
        let caller = signer::address_of(account);
        let vault = borrow_global_mut<Vault>(@exploit_poc);

        // Verify caller is current admin
        assert!(caller == vault.admin, E_NOT_AUTHORIZED);

        vault.admin = new_admin;
    }

    // =========================================================================
    // VULNERABILITY 2: Unauthorized Resource Access
    // =========================================================================

    /// VULNERABLE: Can withdraw from any user's balance
    public entry fun vulnerable_withdraw(
        account: &signer,
        target: address,  // BUG: Can specify any target!
        amount: u64,
    ) acquires UserBalance {
        let balance = borrow_global_mut<UserBalance>(target);

        // No check that caller owns this balance!
        balance.amount = balance.amount - amount;

        // Transfer to caller...
    }

    /// SAFE: Only withdraw from own balance
    public entry fun safe_withdraw(
        account: &signer,
        amount: u64,
    ) acquires UserBalance {
        let caller = signer::address_of(account);

        // Only access caller's own balance
        let balance = borrow_global_mut<UserBalance>(caller);

        assert!(balance.amount >= amount, E_INSUFFICIENT_BALANCE);
        balance.amount = balance.amount - amount;

        // Transfer to caller...
    }

    // =========================================================================
    // VULNERABILITY 3: Arithmetic Overflow
    // =========================================================================

    /// VULNERABLE: Unchecked arithmetic
    public entry fun vulnerable_add_balance(
        account: &signer,
        amount: u64,
    ) acquires UserBalance {
        let caller = signer::address_of(account);
        let balance = borrow_global_mut<UserBalance>(caller);

        // BUG: Can overflow! Move doesn't auto-check in all cases
        balance.amount = balance.amount + amount;
    }

    /// SAFE: Checked arithmetic
    public entry fun safe_add_balance(
        account: &signer,
        amount: u64,
    ) acquires UserBalance {
        let caller = signer::address_of(account);
        let balance = borrow_global_mut<UserBalance>(caller);

        // Check for overflow
        let new_amount = balance.amount + amount;
        assert!(new_amount >= balance.amount, E_OVERFLOW);

        balance.amount = new_amount;
    }

    // =========================================================================
    // VULNERABILITY 4: Capability Leak
    // =========================================================================

    /// VULNERABLE: Capability can be extracted and stored elsewhere
    public fun vulnerable_get_capability(
        account: &signer
    ): AdminCapability acquires AdminCapability {
        let caller = signer::address_of(account);

        // BUG: Returning capability allows caller to store it!
        // They can then use it even after being removed as admin
        move_from<AdminCapability>(caller)
    }

    /// SAFE: Use capability inline, don't return it
    public fun safe_admin_action(
        account: &signer
    ) acquires AdminCapability, Vault {
        let caller = signer::address_of(account);

        // Borrow capability, don't move it
        let cap = borrow_global<AdminCapability>(caller);
        let vault = borrow_global_mut<Vault>(@exploit_poc);

        // Verify capability is valid
        assert!(cap.admin == vault.admin, E_NOT_AUTHORIZED);

        // Perform admin action...
    }

    // =========================================================================
    // VULNERABILITY 5: Reinitialization
    // =========================================================================

    /// VULNERABLE: Can reinitialize existing resource
    public entry fun vulnerable_initialize(
        account: &signer,
    ) {
        let caller = signer::address_of(account);

        // BUG: No check if already exists!
        // Attacker can reset state
        move_to(account, UserBalance {
            amount: 0,
            last_update: timestamp::now_seconds(),
        });
    }

    /// SAFE: Check existence before init
    public entry fun safe_initialize(
        account: &signer,
    ) {
        let caller = signer::address_of(account);

        // Verify not already initialized
        assert!(!exists<UserBalance>(caller), E_ALREADY_INITIALIZED);

        move_to(account, UserBalance {
            amount: 0,
            last_update: timestamp::now_seconds(),
        });
    }

    // =========================================================================
    // VULNERABILITY 6: Flash Loan Pattern Issues
    // =========================================================================

    /// Flash loan callback interface
    struct FlashLoanReceipt {
        amount: u64,
        fee: u64,
    }

    /// VULNERABLE: No repayment verification
    public fun vulnerable_flash_loan(
        account: &signer,
        amount: u64,
    ): (Coin<AptosCoin>, FlashLoanReceipt) acquires Vault {
        let vault = borrow_global_mut<Vault>(@exploit_poc);
        let coins = coin::extract(&mut vault.balance, amount);

        // BUG: Receipt can be discarded!
        // Attacker doesn't need to repay
        (coins, FlashLoanReceipt { amount, fee: amount / 100 })
    }

    /// SAFE: Receipt must be consumed
    public fun safe_flash_loan(
        account: &signer,
        amount: u64,
    ): (Coin<AptosCoin>, FlashLoanReceipt) acquires Vault {
        let vault = borrow_global_mut<Vault>(@exploit_poc);
        let coins = coin::extract(&mut vault.balance, amount);

        (coins, FlashLoanReceipt { amount, fee: amount / 100 })
    }

    /// Repay flash loan - receipt consumption enforced by Move's type system
    public fun repay_flash_loan(
        repayment: Coin<AptosCoin>,
        receipt: FlashLoanReceipt,
    ) acquires Vault {
        let FlashLoanReceipt { amount, fee } = receipt;
        let vault = borrow_global_mut<Vault>(@exploit_poc);

        assert!(coin::value(&repayment) >= amount + fee, E_INSUFFICIENT_BALANCE);
        coin::merge(&mut vault.balance, repayment);
    }

    // =========================================================================
    // VULNERABILITY 7: Time Manipulation
    // =========================================================================

    struct StakingReward has key {
        staked_amount: u64,
        stake_time: u64,
        reward_rate: u64,  // per second
    }

    /// VULNERABLE: Reward calculation can be gamed
    public fun vulnerable_claim_rewards(
        account: &signer,
    ): u64 acquires StakingReward {
        let caller = signer::address_of(account);
        let stake = borrow_global_mut<StakingReward>(caller);

        let current_time = timestamp::now_seconds();
        let time_staked = current_time - stake.stake_time;

        // BUG: In same block, attacker can:
        // 1. Stake huge amount
        // 2. Manipulate timestamp (if possible)
        // 3. Claim inflated rewards
        // 4. Unstake

        let rewards = stake.staked_amount * stake.reward_rate * time_staked;
        stake.stake_time = current_time;

        rewards
    }

    /// SAFE: Minimum staking period + capped rewards
    public fun safe_claim_rewards(
        account: &signer,
    ): u64 acquires StakingReward {
        let caller = signer::address_of(account);
        let stake = borrow_global_mut<StakingReward>(caller);

        let current_time = timestamp::now_seconds();
        let time_staked = current_time - stake.stake_time;

        // Minimum staking period
        assert!(time_staked >= 86400, 0); // 1 day minimum

        // Cap maximum rewards per claim
        let max_time = 30 * 86400; // 30 days max
        let effective_time = if (time_staked > max_time) { max_time } else { time_staked };

        let rewards = stake.staked_amount * stake.reward_rate * effective_time;
        stake.stake_time = current_time;

        rewards
    }
}

// =============================================================================
// TEST MODULE
// =============================================================================
#[test_only]
module exploit_poc::tests {
    use exploit_poc::vulnerabilities;
    use aptos_framework::account;
    use std::signer;

    #[test(attacker = @0x123, victim = @0x456)]
    fun test_missing_signer_exploit(attacker: signer, victim: signer) {
        // Setup...

        // Attacker calls vulnerable_set_admin
        // Should succeed even though attacker is not admin
        // vulnerabilities::vulnerable_set_admin(&attacker, @0x123);

        // Verify attacker is now admin (exploit successful)
    }

    #[test(attacker = @0x123, victim = @0x456)]
    #[expected_failure(abort_code = 1)]  // E_NOT_AUTHORIZED
    fun test_safe_set_admin_rejects_attacker(attacker: signer, victim: signer) {
        // Setup admin as victim...

        // Attacker tries to call safe_set_admin
        // Should fail with E_NOT_AUTHORIZED
        // vulnerabilities::safe_set_admin(&attacker, @0x123);
    }
}
