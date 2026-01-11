# Phase 3: Trusted Execution Environments (TEEs)

Hardware-based security for confidential computing.

---

## Overview

| Topic | Weeks | Outcome |
|-------|-------|---------|
| TEE Concepts | 21-22 | Understand enclave model, attestation |
| Intel SGX | 23-24 | Know SGX architecture, development model |
| Blockchain Apps | 25-26 | Study Secret Network, Oasis, SUAVE |

---

## What Are TEEs?

A Trusted Execution Environment is a secure area of a processor that:
- **Isolates** code and data from the rest of the system
- **Protects** against OS, hypervisor, and physical attacks
- **Attests** that code is running correctly

```
┌─────────────────────────────────────────┐
│           Normal World                   │
│  ┌─────────────────────────────────┐    │
│  │      Operating System           │    │
│  │  ┌─────────┐  ┌─────────┐       │    │
│  │  │  App 1  │  │  App 2  │       │    │
│  │  └─────────┘  └─────────┘       │    │
│  └─────────────────────────────────┘    │
├─────────────────────────────────────────┤
│           Secure World (TEE)            │
│  ┌─────────────────────────────────┐    │
│  │          Enclave                │    │
│  │   (Isolated, Encrypted Memory)  │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## Week 21-22: TEE Concepts

### Core Properties

**1. Isolation**
- Enclave memory encrypted by hardware
- Even OS/hypervisor cannot read enclave memory
- Code runs in protected mode

**2. Confidentiality**
- Data encrypted at rest (in memory)
- Decrypted only inside CPU
- Side-channel attacks are the main threat

**3. Integrity**
- Code cannot be tampered with
- Any modification detected

**4. Attestation**
- Prove to remote party that:
  - Specific code is running
  - It's running in genuine TEE
  - Hardware is authentic

### Attestation Flow

```
1. Enclave generates Report (hash of code + data)
2. Report signed by hardware key
3. Remote party verifies:
   - Signature is from genuine Intel/AMD
   - Code hash matches expected
   - TEE is properly configured
```

### TEE Hardware Landscape

| Platform | Vendor | Notes |
|----------|--------|-------|
| **SGX** | Intel | Most used in crypto, being phased out on consumer CPUs |
| **TDX** | Intel | Next-gen, VM-level isolation |
| **SEV-SNP** | AMD | Full VM encryption |
| **TrustZone** | ARM | Mobile devices |
| **Keystone** | RISC-V | Open source |
| **Nitro Enclaves** | AWS | Cloud-native |

### Threat Model

**What TEEs protect against:**
- Malicious OS/hypervisor
- Physical memory inspection
- Other processes on same machine

**What TEEs DON'T protect against:**
- Side-channel attacks (timing, power analysis)
- Bugs in enclave code itself
- Supply chain attacks on hardware
- Denial of service (host can kill enclave)

### Resources

| Resource | Type |
|----------|------|
| [a16z TEE Primer](https://a16zcrypto.com/posts/article/trusted-execution-environments-tees-primer/) | Overview |
| [Metaschool TEE Guide](https://metaschool.so/articles/trusted-execution-environments-tees) | Web3 focus |
| [awesome-tee-blockchain](https://github.com/dineshpinto/awesome-tee-blockchain) | Curated list |

### Checkpoint

- [ ] Can explain enclave isolation model
- [ ] Understand attestation flow (local vs remote)
- [ ] Know the threat model (what TEEs do/don't protect)
- [ ] Compare SGX vs TDX vs SEV

---

## Week 23-24: Intel SGX

### SGX Architecture

**Application Structure:**
```
┌─────────────────────────────────┐
│        Untrusted Part           │
│   (Regular application code)    │
│         │                       │
│    ECALLs ↓    ↑ OCALLs        │
│         │                       │
├─────────────────────────────────┤
│        Trusted Part             │
│         (Enclave)               │
│   - Sensitive computation       │
│   - Secret key operations       │
│   - Data processing             │
└─────────────────────────────────┘
```

**ECALLs (Enclave Calls):**
- Entry points into the enclave
- Untrusted code calls these functions
- Data is copied in, processed, result returned

**OCALLs (Outside Calls):**
- Enclave calling out to untrusted code
- Used for I/O, network, etc.
- Enclave cannot directly do system calls

### EDL (Enclave Definition Language)

Defines the interface between trusted and untrusted:

```c
// Enclave.edl
enclave {
    // Functions untrusted code can call into enclave
    trusted {
        public int ecall_process_data(
            [in, size=len] uint8_t* data,
            size_t len,
            [out] uint8_t* result
        );
    };

    // Functions enclave can call out to
    untrusted {
        void ocall_print([in, string] const char* str);
        int ocall_read_file(
            [in, string] const char* filename,
            [out, size=buf_len] uint8_t* buf,
            size_t buf_len
        );
    };
};
```

### SGX SDK Setup (Linux)

```bash
# Check SGX support
cpuid | grep -i sgx

# Install SGX SDK
# Download from Intel: https://download.01.org/intel-sgx/
# Or use package manager

# Ubuntu/Debian
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    sudo apt-key add -
sudo apt update
sudo apt install libsgx-enclave-common libsgx-dcap-ql
```

### Hello Enclave Example

```c
// Enclave/Enclave.cpp
#include "Enclave_t.h"
#include <string.h>

int ecall_hello(char* output, size_t len) {
    const char* msg = "Hello from Enclave!";
    if (strlen(msg) + 1 > len) return -1;
    strcpy(output, msg);
    return 0;
}
```

```c
// App/App.cpp
#include "Enclave_u.h"
#include <sgx_urts.h>
#include <stdio.h>

int main() {
    sgx_enclave_id_t eid;
    sgx_status_t ret;

    // Create enclave
    ret = sgx_create_enclave("enclave.signed.so", 1, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave\n");
        return -1;
    }

    // Call into enclave
    char buffer[100];
    int result;
    ret = ecall_hello(eid, &result, buffer, sizeof(buffer));

    printf("Enclave says: %s\n", buffer);

    // Destroy enclave
    sgx_destroy_enclave(eid);
    return 0;
}
```

### Remote Attestation

```
1. Client requests service from Enclave
2. Enclave generates Quote (signed by Intel)
3. Client sends Quote to Intel Attestation Service (IAS)
4. IAS verifies and returns Attestation Report
5. Client trusts Enclave if Report is valid
```

### Side-Channel Attacks

**Known Attacks:**
- **Spectre/Meltdown**: CPU speculation attacks
- **Foreshadow (L1TF)**: L1 cache attack on SGX
- **Plundervolt**: Voltage manipulation
- **SGAxe**: Cache timing attack

**Mitigations:**
- Microcode updates
- Constant-time code
- Memory access obfuscation
- Latest SDK versions

### Resources

| Resource | Type |
|----------|------|
| [SGX 101](https://sgx101.gitbook.io/sgx101/) | Tutorial |
| [Intel SGX Developer Guide](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/get-started.html) | Official |
| [Fleek SGX Guide](https://resources.fleek.xyz/blog/learn/intel-sgx-beginners-guide/) | Beginner |
| [digawp/hello-enclave](https://github.com/digawp/hello-enclave) | Example |

### Checkpoint

- [ ] Understand ECALL/OCALL model
- [ ] Know what EDL files define
- [ ] Understand remote attestation flow
- [ ] Aware of side-channel attack landscape

---

## Week 25-26: Blockchain TEE Applications

### Secret Network

**What it is:**
- First blockchain with private smart contracts
- Built on Cosmos SDK + Intel SGX
- Secret Contracts run inside enclaves

**Architecture:**
```
┌─────────────────────────────────────┐
│           Secret Network            │
├─────────────────────────────────────┤
│  Tendermint Consensus               │
├─────────────────────────────────────┤
│  Cosmos SDK                         │
├─────────────────────────────────────┤
│  Secret Contracts (in SGX)          │
│  - Encrypted inputs                 │
│  - Encrypted state                  │
│  - Encrypted outputs                │
└─────────────────────────────────────┘
```

**Key Features:**
- Encrypted contract state
- Private inputs to contracts
- Viewing keys for data access
- IBC compatible

**Development:**
```rust
// Secret Contract example (Rust + SecretWasm)
use cosmwasm_std::{
    entry_point, DepsMut, Env, MessageInfo, Response, StdResult,
};

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Transfer { recipient, amount } => {
            // This is all encrypted!
            let sender_balance = BALANCES.load(deps.storage, &info.sender)?;
            // ... transfer logic
        }
    }
}
```

### Oasis Network

**Architecture:**
- ParaTime model (parallel runtimes)
- Cipher ParaTime uses TEEs for privacy
- Sapphire ParaTime is EVM-compatible with confidentiality

**Key Differentiator:**
- Separates consensus from computation
- Multiple ParaTimes can run in parallel
- Not all need TEEs (flexibility)

### Flashbots SUAVE

**What it is:**
- "Single Unified Auction for Value Expression"
- TEE-based block building
- MEV protection through private order flow

**How TEEs help:**
```
1. Users submit transactions to SUAVE
2. TEE receives encrypted transactions
3. TEE builds optimal block privately
4. Block revealed only at commitment time
5. No MEV extraction possible
```

**Key Insight:**
- TEEs provide fast, synchronous privacy
- ZK would be too slow for block building
- Trust trade-off: hardware vs math

### Unichain

**TEE Use Case:**
- Optimistic rollup on Ethereum (Oct 2024)
- TEE-based block builder (Flashblocks)
- Pre-confirmations in ~250ms
- MEV redistribution to users

**Architecture:**
```
User → TEE Block Builder → Sequencer → L1
         ↓
    Private ordering
    MEV captured
    Redistributed
```

### Comparison: TEE vs ZK for Privacy

| Aspect | TEE | ZK |
|--------|-----|-----|
| Speed | Fast (native) | Slow (proving) |
| Trust | Hardware vendor | Math only |
| Flexibility | Any computation | Limited by circuit |
| Verification | Attestation | Proof verification |
| Quantum | Vulnerable | Some resistant |

**When to use TEE:**
- Need fast execution
- Complex computation
- Can accept hardware trust

**When to use ZK:**
- Trust-minimized required
- Simpler computations
- Long-term security needed

### iExec

**What it is:**
- Decentralized cloud computing
- TEE-based off-chain computation
- Intel SGX enclaves

**Use Case:**
- Run compute-intensive tasks privately
- Pay with RLC token
- Results verified via attestation

### Resources

| Resource | Type |
|----------|------|
| [Secret Network Docs](https://docs.scrt.network/) | Official |
| [Oasis Sapphire Docs](https://docs.oasis.io/dapp/sapphire/) | Official |
| [SUAVE Specs](https://github.com/flashbots/suave-specs) | Specs |
| [Unichain Docs](https://docs.unichain.org/) | Official |

### Checkpoint

- [ ] Understand Secret Network's privacy model
- [ ] Know how SUAVE uses TEEs for MEV protection
- [ ] Can compare TEE vs ZK for different use cases
- [ ] Studied at least 2 TEE blockchain projects

---

## Phase 3 Completion Checklist

### Concepts
- [ ] Explain TEE isolation and attestation
- [ ] Know the threat model
- [ ] Understand side-channel risks

### SGX
- [ ] Understand ECALL/OCALL architecture
- [ ] Know what attestation proves
- [ ] Reviewed at least one SGX example

### Blockchain Applications
- [ ] Studied Secret Network architecture
- [ ] Understand TEE use in MEV protection
- [ ] Can recommend TEE vs ZK for given use case

---

## Next: Phase 4 - MPC/FHE

[Continue to Phase 4: Multi-Party Computation & Fully Homomorphic Encryption](./zk-phase4-mpc-fhe.md)
