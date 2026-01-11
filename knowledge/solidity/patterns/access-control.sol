// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Access Control Patterns
 * @notice Common patterns for managing permissions in smart contracts
 */

// Pattern 1: Simple Ownable
abstract contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
    }
}

// Pattern 2: Two-Step Ownership Transfer (Safer)
abstract contract Ownable2Step is Ownable {
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    function transferOwnership(address newOwner) public virtual override onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() public virtual {
        require(msg.sender == pendingOwner, "Ownable2Step: caller is not the new owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}

// Pattern 3: Role-Based Access Control (RBAC)
abstract contract AccessControl {
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "AccessControl: account is missing role");
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }

    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }
}

// Pattern 4: Timelock for Critical Operations
abstract contract TimelockController {
    uint256 public constant MINIMUM_DELAY = 1 days;
    uint256 public delay;

    mapping(bytes32 => uint256) public timestamps;

    event CallScheduled(bytes32 indexed id, address target, uint256 value, bytes data, uint256 delay);
    event CallExecuted(bytes32 indexed id, address target, uint256 value, bytes data);

    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 salt
    ) external returns (bytes32) {
        bytes32 id = keccak256(abi.encode(target, value, data, salt));
        require(timestamps[id] == 0, "Already scheduled");

        timestamps[id] = block.timestamp + delay;
        emit CallScheduled(id, target, value, data, delay);
        return id;
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 salt
    ) external payable {
        bytes32 id = keccak256(abi.encode(target, value, data, salt));
        require(timestamps[id] > 0, "Not scheduled");
        require(block.timestamp >= timestamps[id], "Not ready");

        timestamps[id] = 0;
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");

        emit CallExecuted(id, target, value, data);
    }
}

/*
 * USAGE GUIDE:
 *
 * Ownable: Simple contracts with single admin
 * Ownable2Step: When ownership transfer must be deliberate (prevents accidents)
 * AccessControl: Complex systems with multiple roles (MINTER, PAUSER, ADMIN)
 * Timelock: Critical operations (upgrades, large withdrawals)
 *
 * SECURITY NOTES:
 * - Always use 2-step for ownership in production
 * - Timelocks should be used for protocol upgrades
 * - Consider multi-sig for admin roles
 */
