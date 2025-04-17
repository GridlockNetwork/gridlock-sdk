# Gridlock Storage Network Overview

[← Back to README](./README.md)

## Why Gridlock?

Gridlock was built to solve the fundamental security challenges in cryptocurrency storage. Traditional methods of storing crypto assets suffer from critical single points of failure that have led to billions of dollars in losses. These vulnerabilities include:

- **Seed Phrase Vulnerabilities**: A single seed phrase, if lost or stolen, can result in complete loss of funds
- **Centralized Exchange Risks**: Including exchange shutdowns, hacks, internal fraud, and operational failures
- **Hardware Wallet Limitations**: Physical damage, loss, or theft can lead to permanent asset loss
- **Custodial Service Risks**: Dependence on third-party security practices and potential insolvency

Gridlock implements a 3-of-5 Threshold Signature Scheme (TSS), which represents the gold standard in secure crypto storage. This means:

- Your private key is split into 5 pieces (known as keyshares or shards)
- Any 3 of these pieces can work together to sign transactions
- No single piece contains enough information to compromise your funds
- The system remains operational even if 2 pieces are lost or compromised

This technology enables truly resilient long-term crypto storage by:

- Eliminating single points of failure
- Providing built-in redundancy
- Allowing for secure recovery mechanisms
- Maintaining complete user control without reliance on centralized entities

The system is made up of four main components:

## 1. CLI

The CLI is the simplest way to use Gridlock. It lets anyone create secure wallets, manage guardians, and run a distributed network. Whether you're setting up a wallet for yourself or managing a network for others, the CLI is designed to be easy to use from the command line. It uses the SDK internally to perform all operations.

## 2. SDK

The SDK is for developers who want to build on top of the Gridlock storage network. It provides all the logic needed to manage keys, guardians, signing, and recovery. Developers can use the SDK to build their own interfaces, tools, or even run their own private storage networks.

**Note**: The Gridlock mobile app is built using the SDK and serves as a consumer-friendly example of how the SDK can be used to connect people to the network.

## 3. Orchestration Node

The orchestration node ("orch node") makes distributed signing possible. It handles the rounds of communication needed between the user and the guardian nodes. It cannot see or change the messages being passed—it only routes encrypted packets from one place to another. Its role is to ensure the process runs smoothly and securely without controlling any user assets.

## 4. Guardian Node

The guardian node is the core of the system. Each guardian holds one piece of a user's encrypted key and participates in signing and recovery. Guardian nodes use threshold signature cryptography, meaning several guardians must work together to sign a transaction. If one guardian is lost or even compromised, the system still works. This design removes single points of failure and keeps user assets safe.
