# Getting to Blockchain Core Developer

You build on blockchains. These roles build the blockchains themselves. The gap isn't knowledge, it's the layer you operate at. Here's what closes it.

## The Gap

Your current stack operates at the application layer: smart contracts, DeFi integrations, dApps. Core blockchain roles operate at the infrastructure layer: node software, P2P networking, consensus engines, state databases, transaction pools. Same industry, different engineering discipline entirely.

## What You Need

### 1. Systems-Level Rust (not Anchor Rust)

Anchor abstracts away everything that makes Rust relevant for infrastructure work. You need bare-metal Rust: manual memory management, lifetimes, async runtimes (tokio), unsafe blocks, FFI, zero-copy deserialization.

**Do this:**
- Work through the Rust Book end-to-end (you probably skipped chapters 10, 15, 16, 19)
- Build something with tokio directly: a TCP server, a simple P2P node, a concurrent task scheduler
- Read and contribute to reth (Paradigm's Ethereum client in Rust) — start with "good first issue" tags
- Build a simplified blockchain node from scratch: block struct, chain validation, peer discovery, state storage

**Target:** Be able to read reth or Solana validator code and understand what's happening without looking things up every line.

### 2. Go (Golang)

Most blockchain clients are written in Go (geth, BSC node, Tendermint, Cosmos SDK). BNB Chain's core client is a geth fork. You can't contribute to it without Go.

**Do this:**
- Learn Go basics (1-2 weeks if you already know TypeScript — the language is intentionally simple)
- Read through go-ethereum's core packages: core/types, consensus, p2p, eth
- Build a simple Ethereum block parser in Go
- Contribute to BSC's go-ethereum fork (github.com/bnb-chain/bsc)

### 3. Distributed Systems Fundamentals

You need to understand these not as a user, but as an implementer:

- **Consensus algorithms:** Implement Raft from scratch. Then study PBFT, Tendermint BFT, and how PoS/PoA actually work at the code level (not the whitepaper level).
- **P2P networking:** libp2p, Kademlia DHT, gossip protocols. Understand how nodes discover each other, how blocks propagate, how transactions get to the mempool.
- **Concurrent programming:** Goroutines/channels (Go), tokio tasks/mutexes (Rust). Race conditions, deadlocks, lock-free data structures. This is the daily reality of node development.
- **State management:** How Merkle Patricia Tries work, how state is stored and pruned, how light clients verify state.

**Do this:**
- MIT 6.824 Distributed Systems course (free, labs are in Go) — this is the gold standard
- Implement a Raft consensus node (the MIT course includes this)
- Read the Ethereum Yellow Paper and trace how geth implements each section
- Read the Gasper paper (Ethereum's actual consensus) or Tendermint paper

### 4. Low-Level Networking and OS Concepts

- TCP/UDP socket programming
- Serialization formats (RLP, SSZ, protobuf, borsh)
- Memory-mapped I/O, disk I/O patterns for databases
- Linux process management, systemd, profiling (perf, flamegraphs)

**Do this:**
- Build a simple wire protocol in Rust or Go (serialize/deserialize custom messages over TCP)
- Profile a running geth or reth node with pprof or perf and understand the output
- Understand LevelDB/RocksDB at a basic level (these are the state databases)

### 5. Open Source Contributions (the actual resume builder)

Nobody will hire you for a core dev role based on personal projects alone. They want to see you operating in large, complex codebases with other engineers.

**Priority targets (pick one and go deep):**

| Project | Language | Why |
|---------|----------|-----|
| **reth** (Paradigm) | Rust | Actively seeking contributors, excellent mentorship, directly relevant to EVM chains |
| **BSC** (BNB Chain) | Go | The exact codebase for the role you want |
| **Solana validator** | Rust | You already have Solana context from Anchor work |
| **Lighthouse/Prysm** | Rust/Go | Ethereum consensus clients, slightly easier entry point |

**Do this:**
- Pick one client, run it locally, read the architecture docs
- Start with documentation PRs and test coverage PRs to learn the codebase
- Graduate to bug fixes, then small features
- Aim for 5-10 merged PRs over 3-6 months

### 6. CS Fundamentals (filling the degree gap)

Without a CS degree, you need to demonstrate the knowledge through work. The areas that matter most for infrastructure:

- **Data structures:** B-trees, tries (especially Merkle Patricia Tries), hash maps, bloom filters
- **Algorithms:** Graph algorithms (used in P2P), hashing, sorting for transaction ordering
- **Operating systems:** Process scheduling, memory management, I/O models (these show up everywhere in node development)
- **Computer networking:** TCP/IP stack, NAT traversal, UDP hole punching (critical for P2P)

**Do this:**
- Nand2Tetris (free) for computer architecture basics
- OSTEP (free) for operating systems
- Computer Networking: A Top-Down Approach for networking fundamentals

## Realistic Timeline

**Months 1-3:** Rust Book deep dive + Go basics + MIT 6.824 started + run a blockchain node locally

**Months 3-6:** First open-source PRs to reth or BSC + implement Raft + build a toy blockchain node

**Months 6-9:** Regular contributor to one client + deeper consensus/networking understanding + can read and discuss client architecture

**Months 9-12:** Multiple merged PRs in a production client + can discuss tradeoffs in consensus design, state management, networking at interview level

After 6 months of focused work, you'd be a credible candidate for core dev roles. After 12 months, you'd be competitive for the BNB Chain posting level.

## What You Already Have That Transfers

- Blockchain domain knowledge (you understand what these systems are trying to do)
- Security mindset (from Sentinel and audit work)
- ZK/cryptography exposure (rare even among core devs)
- Solana/Rust starting point (even if it's Anchor-level)
- Ability to ship (hackathon track record proves work ethic)

The path is systems Rust/Go + distributed systems theory + open-source contributions to an actual client. Everything else is secondary.
