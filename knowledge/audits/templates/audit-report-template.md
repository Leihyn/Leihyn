# Security Audit Report

## Project: [PROJECT_NAME]
## Auditor: [YOUR_NAME]
## Date: [DATE]
## Commit: [COMMIT_HASH]

---

## Executive Summary

### Overview
[Brief description of the project and its purpose]

### Scope
| Contract | SLOC | Purpose |
|----------|------|---------|
| Contract1.sol | 150 | Main entry point |
| Contract2.sol | 200 | Token logic |

### Findings Summary
| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |
| Gas | 0 |

### Audit Timeline
- Start Date: [DATE]
- End Date: [DATE]
- Total Hours: [HOURS]

---

## Findings

### [H-01] [Finding Title]

**Severity:** High

**Status:** [Open/Acknowledged/Fixed]

**Location:** `Contract.sol#L50-L60`

**Description:**
[Detailed description of the vulnerability]

**Impact:**
[What can go wrong and how severe]

**Proof of Concept:**
```solidity
// Attack scenario or test case
function testExploit() public {
    // Steps to reproduce
}
```

**Recommendation:**
```solidity
// Suggested fix
```

**Team Response:**
[Protocol team's response]

---

### [M-01] [Finding Title]

**Severity:** Medium

**Status:** [Open/Acknowledged/Fixed]

**Location:** `Contract.sol#L100`

**Description:**
[Description]

**Impact:**
[Impact]

**Recommendation:**
[Fix]

---

### [L-01] [Finding Title]

**Severity:** Low

**Status:** [Open/Acknowledged/Fixed]

**Location:** `Contract.sol#L200`

**Description:**
[Description]

**Recommendation:**
[Fix]

---

### [I-01] [Informational Finding]

**Severity:** Informational

**Location:** `Contract.sol#L300`

**Description:**
[Best practice suggestion or informational note]

---

### [G-01] [Gas Optimization]

**Severity:** Gas

**Location:** `Contract.sol#L400`

**Description:**
[Gas optimization opportunity]

**Gas Savings:** ~500 gas per call

**Recommendation:**
```solidity
// Optimized code
```

---

## Scope Details

### Files in Scope
```
src/
├── Contract1.sol
├── Contract2.sol
└── libraries/
    └── Library.sol
```

### Files Out of Scope
- Test files
- Mock contracts
- External dependencies (OpenZeppelin, Solmate)

---

## Methodology

### Tools Used
- Slither (static analysis)
- Foundry (testing, fuzzing)
- Manual review

### Areas of Focus
1. Access control
2. Reentrancy
3. Oracle manipulation
4. Integer arithmetic
5. Token handling
6. Business logic

### Test Coverage
| Contract | Line Coverage | Branch Coverage |
|----------|--------------|-----------------|
| Contract1 | 95% | 90% |
| Contract2 | 88% | 85% |

---

## Architecture Review

### System Overview
[Diagram or description of system architecture]

### Trust Assumptions
1. Admin keys are secured with multi-sig
2. Oracle prices are accurate within acceptable bounds
3. [Other assumptions]

### Centralization Risks
| Risk | Severity | Notes |
|------|----------|-------|
| Admin can pause | Medium | Required for emergency |
| Admin can upgrade | High | Timelock in place |

---

## Disclaimer

This audit does not guarantee the absence of vulnerabilities. The audit is a time-boxed review of the code at the specified commit hash. Changes made after the audit may introduce new vulnerabilities.

This report is not investment advice and should not be used as the sole basis for any decision regarding the protocol.

---

## About [YOUR_NAME/COMPANY]

[Brief bio or company description]

**Contact:** [email/social]

---

## Appendix

### A. Severity Classification

| Severity | Description |
|----------|-------------|
| Critical | Direct loss of funds, permanent freezing, protocol insolvency |
| High | Conditional loss of funds, governance manipulation |
| Medium | Griefing, limited impact vulnerabilities |
| Low | Best practice violations, minor issues |
| Informational | Suggestions and observations |
| Gas | Gas optimization opportunities |

### B. Finding Status

| Status | Description |
|--------|-------------|
| Open | Not yet addressed |
| Acknowledged | Team aware, won't fix |
| Fixed | Remediated in specified commit |
| Disputed | Team disagrees with finding |
