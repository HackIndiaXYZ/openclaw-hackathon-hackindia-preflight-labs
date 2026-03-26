<div align="center">

# 🛡️ PreFlight

### Zero-Trust Pre-Transaction Firewall for Arbitrum DeFi

*Verify before you execute. Trust nothing. Simulate everything.*

<br/>

[![Arbitrum](https://img.shields.io/badge/Chain-Arbitrum-28A0F0?style=for-the-badge&logo=arbitrum&logoColor=white)](https://arbitrum.io)
[![Chainlink CRE](https://img.shields.io/badge/Chainlink-CRE_Simulation-375BD2?style=for-the-badge&logo=chainlink&logoColor=white)](https://chain.link)
[![Chainlink Automation](https://img.shields.io/badge/Chainlink-Automation-375BD2?style=for-the-badge&logo=chainlink&logoColor=white)](https://automation.chain.link)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=for-the-badge&logo=solidity&logoColor=white)](https://soliditylang.org)
[![Foundry](https://img.shields.io/badge/Tests-Foundry-F05032?style=for-the-badge)](https://book.getfoundry.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

**OpenClaw Hackathon — HackIndia 2026 Submission**

 Track: **Blockchain & Emerging Technologies**

<br/>

> PreFlight is a pre-execution integrity firewall that intercepts DeFi transactions **before they are signed**, analyzes on-chain state, simulates execution via Chainlink CRE, and blocks unsafe transactions — protecting users from flash-loan manipulation, malicious tokens, and vault exploits in real time.

</div>

---

## Demo Video

>  **[Watch the Demo →](YOUR_DEMO_VIDEO_LINK_HERE)**

---

## 🔗 Original Development Repo

Development Repo : https://github.com/Sourav-IIITBPL/preflight 

---

## Overview

PreFlight is a blockchain security system that verifies the safety of a transaction before it is executed.

It acts as a pre-execution firewall for DeFi by analyzing transaction intent, on-chain state, and execution behavior in real time.

Unlike existing tools that rely on UI previews, price estimates, or static checks, PreFlight evaluates the actual execution path of a transaction before it is submitted.

By combining state validation, simulation, and trace analysis, it ensures that what the user expects aligns with what will happen on-chain.

---

## Problem

In DeFi, users often lose funds even when all visible indicators appear safe:

- Interfaces display expected outputs  
- Slippage settings are within acceptable limits  
- Protocols have undergone audits  

These failures occur because current systems do not verify how a transaction will actually execute.

Critical risks arise from execution-level behaviors such as:

- Flash-loan manipulation that temporarily distorts on-chain state  
- Hidden execution paths through delegatecalls and internal calls  
- Unexpected token transfers or approval escalations  
- Mismatch between quoted results and actual execution outcomes  

Existing tools validate expected results, but they do not validate execution integrity.

---

## Core Insight

The most critical security gap in blockchain transactions exists between:

- User signing a transaction and the transaction being executed on-chain

This is the only point where unsafe execution can still be prevented.
Once a transaction is submitted, execution is irreversible.

PreFlight is designed to secure this exact boundary by verifying transactions before they reach the chain.

---

## Solution

PreFlight introduces a pre-transaction verification layer that determines whether a transaction should be allowed, warned, or blocked before execution.

Flow:
```
User Intent -> PreFlight Verification -> Decision -> Execute or Abort
```
The system performs multi-layer analysis by evaluating:

- **On-chain state conditions** to detect manipulation or abnormal protocol behavior  
- **Simulated execution results** to predict actual transaction outcomes  
- **Execution trace behavior** to uncover hidden calls and fund flows  
- **Accounting correctness** to ensure balance changes match user intent  

Based on these signals, PreFlight produces a deterministic and explainable decision, enabling users to avoid unsafe transactions before committing funds.

---

## System Architecture

PreFlight operates across three independent verification layers.

### 1. On-Chain Guards

Fast and deterministic checks on live blockchain state:

- Swap Guard  
  Detects price manipulation using TWAP vs spot deviation  

- Liquidity Guard  
  Identifies unsafe liquidity operations, mintable tokens, and abnormal approvals  

- Vault Guard  
  Verifies ERC-4626 vault invariants and exchange rate consistency  

---

### 2. Off-Chain Simulation

The transaction is simulated before execution:

- Forks current blockchain state  
- Executes exact calldata  
- Captures full execution trace  

This allows detection of:

- Delegatecall to unknown contracts  
- Unexpected fund flows  
- Approval escalation patterns  
- Hidden internal calls  
- Accounting inconsistencies  

---

### 3. Policy Engine

All signals are aggregated into a deterministic decision:

- Safe → Transaction allowed  
- Warning → User confirmation required  
- Critical → Transaction blocked  

This removes ambiguity and avoids black-box scoring.

---

### 4. Verifiable Risk Report

Each transaction analysis can generate an on-chain non-transferable NFT containing:

- Full execution analysis  
- Detected risks  
- Trace-level data  
- Reproducible verification data  

This ensures transparency and auditability.

---

## What Was Built During the Hackathon

From March 6 to the submission deadline, PreFlight was designed, implemented, and integrated as a complete end-to-end pre-transaction security system.

The following components were built and connected into a working pipeline:

- **Core Guard System**  
  Developed protocol-aware guard contracts for swaps, liquidity interactions, and ERC-4626 vaults to validate on-chain state integrity in real time  

- **PreFlightRouter (Execution Entry Point)**  
  Implemented a unified routing layer that intercepts user transaction intent and orchestrates the full verification pipeline  

- **Policy Engine (Decision Layer)**  
  Designed a deterministic aggregation system that converts multi-source risk signals into clear outcomes: allow, warn, or block  

- **Simulation Integration (Chainlink CRE)**  
  Integrated off-chain transaction simulation to execute exact calldata on a forked state and capture full execution traces  

- **Trace-Based Risk Detection**  
  Built logic to analyze execution traces and detect hidden behaviors such as delegatecalls, unexpected fund flows, and approval escalations  

- **NFT-Based Risk Reporting System**  
  Implemented a verifiable reporting mechanism that stores transaction analysis as a non-transferable on-chain NFT  

- **Frontend Interface**  
  Developed a user-facing interface to construct transaction intent, visualize risks, and interact with the verification system  

- **Browser Extension**  
  Built an extension layer that enables real-time interception and verification of user transactions before submission   

---

## Innovation

PreFlight introduces a new security paradigm for blockchain transactions by shifting protection from reactive analysis to proactive prevention.

Instead of analyzing transactions after execution or relying on surface-level previews, PreFlight verifies what will actually happen before the transaction is sent on-chain.

Key innovations include:

- **Pre-Execution Security Model**  
  Moves the security boundary to the only point where loss can be prevented — before transaction execution  

- **Execution-Aware Verification**  
  Goes beyond static checks by simulating real transaction behavior and analyzing execution traces  

- **Multi-Layer Risk Analysis**  
  Combines on-chain state validation, off-chain simulation, and accounting verification into a unified system  

- **Deterministic and Explainable Decisions**  
  Eliminates black-box scoring by providing structured, reproducible, and transparent risk outcomes  

- **Protocol-Agnostic Security Layer**  
  Designed as a modular system that can integrate across AMMs, vaults, and emerging DeFi primitives  

PreFlight is not a monitoring or analytics tool.  
It is a transaction firewall that actively prevents unsafe interactions in blockchain systems.

---

## Technical Depth

PreFlight is designed as a multi-layered security system combining on-chain verification, off-chain simulation, and execution trace analysis.

The project demonstrates:

- **Smart Contract Security Engineering**  
  Development of deterministic guard contracts that validate protocol-specific invariants such as pricing integrity, liquidity safety, and vault accounting correctness  

- **Execution Trace Analysis**  
  Deep inspection of simulated transaction traces to detect hidden behaviors including delegatecalls, unexpected token flows, approval escalations, and internal call patterns  

- **Deterministic Simulation Infrastructure**  
  Integration of Chainlink CRE to fork live blockchain state and execute exact calldata, ensuring reproducible and verifiable transaction outcomes  

- **Modular Verification Architecture**  
  Separation of concerns across Guards, Simulation Layer, and Policy Engine, enabling easy extension to new protocols and security checks  

- **Cross-Layer Risk Aggregation**  
  Structured signal collection from multiple sources (state, execution, accounting) and deterministic decision-making via a unified policy engine  

The system is protocol-agnostic and designed to scale across different DeFi primitives, AMMs, and vault standards without architectural changes.

---

## Real-World Impact

PreFlight addresses a fundamental gap in blockchain security: the inability to verify transaction safety before execution.

Today, most losses in DeFi occur not due to obvious bugs, but due to subtle execution-level risks such as manipulated state, hidden logic paths, and unexpected asset flows.

PreFlight mitigates these risks by introducing a pre-execution verification layer that:

- Prevents financial loss by blocking unsafe transactions before they are submitted  
- Detects complex attack vectors such as flash-loan manipulation, malicious token behavior, and vault exploits  
- Provides users with transparent, explainable risk assessments instead of opaque warnings  
- Enables safer interaction with complex DeFi protocols without requiring deep technical expertise  

By shifting security from reactive analysis to proactive prevention, PreFlight has the potential to significantly improve trust and safety across the DeFi ecosystem. 


---

## Future Scope

PreFlight is currently deployed and tested on the Arbitrum testnet as a proof-of-concept security layer for DeFi transactions.

The next phase of development focuses on scaling both coverage and adoption:

- Multi-chain expansion to networks such as Ethereum, Polygon, and other EVM-compatible chains  
- Integration with major AMMs (Uniswap, SushiSwap, Curve) and DeFi primitives  
- Support for a wider range of vault standards and yield protocols beyond ERC-4626  
- Native wallet integrations (MetaMask, Rabby) for seamless pre-transaction verification  
- MEV-aware simulation to detect sandwich and frontrunning risks  
- Advanced policy customization for users, protocols, and institutions  
- Developer SDK for integrating PreFlight verification into dApps and routers  

The long-term vision is to establish PreFlight as a standard security layer across DeFi — ensuring that every transaction is verified before execution, not after failure.