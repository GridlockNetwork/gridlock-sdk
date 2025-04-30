# Gridlock SDK

This is the core SDK that powers everything in the Gridlock system—including the [Gridlock CLI](https://github.com/GridlockNetwork/gridlock-cli) and the [Gridlock mobile app](https://gridlock.network). It handles user creation, guardian management, signing, and recovery using Gridlock's distributed architecture.

To understand how the full system works, see [SystemOverview.md](./SystemOverview.md).  
Related: [Orch Node](https://github.com/GridlockNetwork/orch-node) | [Guardian Node](https://github.com/GridlockNetwork/guardian-node) | [SDK](https://github.com/GridlockNetwork/gridlock-sdk)  
For full CLI and SDK documentation [see the developer docs](https://docs.gridlock.network/developer-docs/sdk-cli-documentation).

## Quick Start

Install the SDK:

```
npm install gridlock-sdk
```

Then in your code:

```ts
import { Gridlock } from "gridlock-sdk";

const gridlock = new Gridlock({
  apiKey: "your-api-key",
  baseUrl: "https://api.gridlock.network",
  debug: true,
});
```

For full SDK documentation, check out the [developer docs](https://docs.gridlock.network/developer-docs/sdk-cli-documentation).

---

## Local SDK Development

If you're cloning this repo, you're likely doing development work. Here's how to get started:

1. Install dependencies, build, and link the package:

```
npm install
npm run build
npm link
```

2. In any project where you want to test your local changes (e.g. gridlock-cli):

```
npm link gridlock-sdk
```

3. Start the development server to automatically rebuild when you make changes:

```
npm run dev
```

For general usage instructions, see the [Quick Start](#quick-start) section above.

All further usage is documented in the [developer docs](https://docs.gridlock.network/developer-docs/sdk-cli-documentation).

---

## When to Use This SDK

You don't need to clone this repo unless you're modifying behavior or building on top of the core SDK.

Use this repo if:

- You want to customize how Gridlock works
- You're developing features or extensions
- You need to test SDK changes locally in other projects
- You want to contribute to Gridlock's core infrastructure

For general use, just run:

```
npm install gridlock-sdk
```

---

## How to Help

This SDK is the backbone of Gridlock. If you want to improve developer experience, add features, or clean up internals—this is the place.

- Tighten up error handling
- Extend support for new flows
- Improve config and types
- Help document edge cases

## Join the Network

This code is yours to use — but it’s even better when you’re part of the official Gridlock network.

By running [guardian nodes](https://github.com/GridlockNetwork/guardian-node), you can earn rewards while helping secure the network.

Join the community: [gridlock.network/join](https://gridlock.network/join)
