/// Sui Move Exploit PoC Template
/// Sui-specific attack vectors and vulnerabilities
///
/// SUI UNIQUE CONCEPTS:
/// 1. Object Model (owned, shared, immutable)
/// 2. Programmable Transaction Blocks (PTBs)
/// 3. Dynamic Fields
/// 4. TxContext for transaction info
/// 5. Clock for timestamps

module exploit_poc::sui_vulnerabilities {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};
    use sui::clock::{Self, Clock};
    use sui::dynamic_field as df;

    // =========================================================================
    // ERROR CODES
    // =========================================================================
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;
    const E_INVALID_STATE: u64 = 3;

    // =========================================================================
    // DATA STRUCTURES
    // =========================================================================

    /// Capability for admin operations
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Shared pool that multiple users interact with
    public struct SharedPool has key {
        id: UID,
        balance: Balance<SUI>,
        total_shares: u64,
    }

    /// User's owned position
    public struct UserPosition has key, store {
        id: UID,
        owner: address,
        shares: u64,
    }

    /// For dynamic field attacks
    public struct Registry has key {
        id: UID,
    }

    // =========================================================================
    // VULNERABILITY 1: Shared Object Race Condition
    // =========================================================================

    /// VULNERABLE: Race condition on shared object
    /// Multiple transactions can read the same balance before any deducts
    public fun vulnerable_withdraw(
        pool: &mut SharedPool,
        position: &mut UserPosition,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        // Multiple txs can pass this check simultaneously!
        let share_value = (balance::value(&pool.balance) * position.shares) / pool.total_shares;
        assert!(share_value >= amount, E_INSUFFICIENT_BALANCE);

        // By the time this executes, balance might be drained
        let withdrawn = balance::split(&mut pool.balance, amount);

        // Update shares (but damage already done)
        let shares_to_burn = (amount * pool.total_shares) / balance::value(&pool.balance);
        position.shares = position.shares - shares_to_burn;
        pool.total_shares = pool.total_shares - shares_to_burn;

        coin::from_balance(withdrawn, ctx)
    }

    /// SAFER: Use atomic check-and-withdraw pattern
    public fun safe_withdraw(
        pool: &mut SharedPool,
        position: &mut UserPosition,
        shares_to_burn: u64,  // Specify shares, not amount
        ctx: &mut TxContext,
    ): Coin<SUI> {
        assert!(position.shares >= shares_to_burn, E_INSUFFICIENT_BALANCE);

        // Calculate amount AFTER share deduction is committed
        let amount = (balance::value(&pool.balance) * shares_to_burn) / pool.total_shares;

        // Atomic: deduct shares THEN withdraw
        position.shares = position.shares - shares_to_burn;
        pool.total_shares = pool.total_shares - shares_to_burn;

        let withdrawn = balance::split(&mut pool.balance, amount);
        coin::from_balance(withdrawn, ctx)
    }

    // =========================================================================
    // VULNERABILITY 2: Object Ownership Confusion
    // =========================================================================

    /// VULNERABLE: Transfers object without ownership verification
    public fun vulnerable_transfer(
        position: UserPosition,  // Takes ownership but doesn't verify!
        recipient: address,
    ) {
        // Anyone who has the object can transfer it
        // No check that tx sender is the owner
        transfer::public_transfer(position, recipient);
    }

    /// SAFE: Verify ownership before transfer
    public fun safe_transfer(
        position: UserPosition,
        recipient: address,
        ctx: &TxContext,
    ) {
        assert!(position.owner == tx_context::sender(ctx), E_NOT_AUTHORIZED);
        transfer::public_transfer(position, recipient);
    }

    // =========================================================================
    // VULNERABILITY 3: Missing Capability Check
    // =========================================================================

    /// VULNERABLE: Admin function without AdminCap
    public fun vulnerable_drain_pool(
        pool: &mut SharedPool,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        // Anyone can drain the pool!
        let all = balance::withdraw_all(&mut pool.balance);
        coin::from_balance(all, ctx)
    }

    /// SAFE: Requires AdminCap
    public fun safe_drain_pool(
        _cap: &AdminCap,  // Proves admin ownership
        pool: &mut SharedPool,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let all = balance::withdraw_all(&mut pool.balance);
        coin::from_balance(all, ctx)
    }

    // =========================================================================
    // VULNERABILITY 4: PTB (Programmable Transaction Block) Attack
    // =========================================================================

    /// These functions can be chained in a PTB for flash-loan-like attacks
    ///
    /// Attack flow in single PTB:
    /// 1. borrow() - Get large amount
    /// 2. manipulate_price() - Move price using borrowed funds
    /// 3. exploit_at_manipulated_price() - Profit from manipulation
    /// 4. repay() - Return borrowed funds

    public struct FlashLoanReceipt {
        amount: u64,
    }

    /// VULNERABLE: Receipt can be created but not enforced for return
    public fun vulnerable_borrow(
        pool: &mut SharedPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<SUI>, FlashLoanReceipt) {
        let borrowed = balance::split(&mut pool.balance, amount);
        (
            coin::from_balance(borrowed, ctx),
            FlashLoanReceipt { amount }
        )
    }

    // Receipt just gets dropped - no enforcement!

    /// SAFER: Hot potato pattern - receipt MUST be consumed
    public struct HotPotatoReceipt {
        pool_id: address,
        amount: u64,
    }
    // Note: No 'drop' ability - MUST be consumed!

    public fun safe_borrow(
        pool: &mut SharedPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<SUI>, HotPotatoReceipt) {
        let borrowed = balance::split(&mut pool.balance, amount);
        (
            coin::from_balance(borrowed, ctx),
            HotPotatoReceipt {
                pool_id: object::uid_to_address(&pool.id),
                amount
            }
        )
    }

    public fun repay(
        pool: &mut SharedPool,
        payment: Coin<SUI>,
        receipt: HotPotatoReceipt,
    ) {
        let HotPotatoReceipt { pool_id, amount } = receipt;

        assert!(pool_id == object::uid_to_address(&pool.id), E_INVALID_STATE);
        assert!(coin::value(&payment) >= amount, E_INSUFFICIENT_BALANCE);

        balance::join(&mut pool.balance, coin::into_balance(payment));
    }

    // =========================================================================
    // VULNERABILITY 5: Dynamic Field Attacks
    // =========================================================================

    /// VULNERABLE: Anyone can add dynamic fields
    public fun vulnerable_add_field<T: store>(
        registry: &mut Registry,
        key: vector<u8>,
        value: T,
    ) {
        // No authorization - anyone can add fields!
        df::add(&mut registry.id, key, value);
    }

    /// This enables attacks like:
    /// 1. Add malicious data as dynamic field
    /// 2. Other functions read this data thinking it's legitimate
    /// 3. Exploit the confusion

    /// SAFE: Authorized field addition
    public fun safe_add_field<T: store>(
        _cap: &AdminCap,
        registry: &mut Registry,
        key: vector<u8>,
        value: T,
    ) {
        df::add(&mut registry.id, key, value);
    }

    // =========================================================================
    // VULNERABILITY 6: Clock Manipulation Assumptions
    // =========================================================================

    public struct TimeLock has key {
        id: UID,
        unlock_time: u64,
        value: Balance<SUI>,
    }

    /// VULNERABLE: Assumes Clock is always accurate
    public fun vulnerable_unlock(
        timelock: TimeLock,
        clock: &Clock,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let TimeLock { id, unlock_time, value } = timelock;

        // Clock can be slightly manipulated by validators
        // Also: what if clock object is from different network?
        assert!(clock::timestamp_ms(clock) >= unlock_time, E_NOT_AUTHORIZED);

        object::delete(id);
        coin::from_balance(value, ctx)
    }

    /// SAFER: Use shared Clock object explicitly
    /// The system Clock (0x6) is the canonical one
    public fun safe_unlock(
        timelock: TimeLock,
        clock: &Clock,  // Should be validated as 0x6 at call site
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let TimeLock { id, unlock_time, value } = timelock;

        // Add buffer for clock drift
        let buffer = 60_000; // 1 minute buffer
        assert!(clock::timestamp_ms(clock) >= unlock_time + buffer, E_NOT_AUTHORIZED);

        object::delete(id);
        coin::from_balance(value, ctx)
    }

    // =========================================================================
    // VULNERABILITY 7: Object Type Confusion
    // =========================================================================

    /// If two structs have similar layouts, confusion is possible
    public struct RealVault has key {
        id: UID,
        balance: Balance<SUI>,
        admin: address,
    }

    public struct FakeVault has key {
        id: UID,
        balance: Balance<SUI>,
        admin: address,  // Attacker controls this!
    }

    /// Functions that take &UID or generic objects might be confused
    /// Always use strongly typed parameters

    // =========================================================================
    // AUDIT CHECKLIST FOR SUI
    // =========================================================================

    /// When auditing Sui contracts, check:
    ///
    /// 1. SHARED OBJECTS
    ///    [ ] Race conditions considered?
    ///    [ ] Atomic operations where needed?
    ///    [ ] Ordering dependencies documented?
    ///
    /// 2. OBJECT OWNERSHIP
    ///    [ ] Ownership verified before operations?
    ///    [ ] transfer::public_transfer vs transfer::transfer correct?
    ///    [ ] Object capabilities properly used?
    ///
    /// 3. PTB RESISTANCE
    ///    [ ] Flash-loan patterns considered?
    ///    [ ] Hot potato enforced where needed?
    ///    [ ] State valid at transaction boundaries?
    ///
    /// 4. DYNAMIC FIELDS
    ///    [ ] Access control on field operations?
    ///    [ ] Field existence validated before use?
    ///    [ ] Type safety maintained?
    ///
    /// 5. CLOCK USAGE
    ///    [ ] Using system Clock (0x6)?
    ///    [ ] Buffer for clock drift?
    ///    [ ] Time-based logic robust?
    ///
    /// 6. CAPABILITIES
    ///    [ ] AdminCap/OwnerCap for privileged ops?
    ///    [ ] Capability creation controlled?
    ///    [ ] Capability transfer restricted?
}

// =============================================================================
// TEST MODULE
// =============================================================================
#[test_only]
module exploit_poc::sui_tests {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::coin;
    use sui::sui::SUI;
    use exploit_poc::sui_vulnerabilities::{Self as vuln, SharedPool, UserPosition};

    #[test]
    fun test_race_condition_concept() {
        // This test demonstrates the race condition concept
        // In real Sui, multiple transactions can be processed in parallel
        // against the same shared object

        let admin = @0xADMIN;
        let user1 = @0xUSER1;
        let user2 = @0xUSER2;

        let mut scenario = ts::begin(admin);

        // Setup: Create pool with 100 SUI, two users with 50 shares each
        // ...

        // Conceptual attack:
        // T1 (user1): Read balance=100, shares=50 -> can withdraw 50
        // T2 (user2): Read balance=100, shares=50 -> can withdraw 50
        // Both pass validation
        // T1 executes: withdraws 50, balance now 50
        // T2 executes: tries to withdraw 50, but only 50 left
        // Result: One user gets less than expected

        ts::end(scenario);
    }

    #[test]
    fun test_ptb_flash_loan_concept() {
        // Demonstrates PTB flash loan pattern
        // In a single PTB:
        // Move 1: Borrow 1000 SUI
        // Move 2: Use borrowed SUI to manipulate DEX price
        // Move 3: Trade at manipulated price for profit
        // Move 4: Repay 1000 SUI
        // Net: Attacker profits from price manipulation

        // This is why hot potato pattern is important!
    }
}
