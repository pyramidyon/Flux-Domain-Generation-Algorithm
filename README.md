# Flux-Domain-Generation-Algorithm

# Flux Domain Generation Algorithm (@Pyramidyon)
**Demo:** 

[![Flux DGA demo](https://raw.githubusercontent.com/pyramidyon/Flux-Domain-Generation-Algorithm/main/flux-dga.png)](https://github.com/pyramidyon/Flux-Domain-Generation-Algorithm/raw/main/flux-dga-demo.mp4)

## Introduction

Domain Generation Algorithms (DGAs) are widely used in malware to generate domain names dynamically. These algorithms often contain flaws, including susceptibility to reverse engineering. Moreover, for effective operation, infected machines must have accurately set timezones—a condition generally met.

This prompts a critical question: What is common among most malware? The answer lies in their primary function—to establish a network connection.

## Traditional Approach

Traditionally, DGA-based malware is tackled by analyzing DGA characteristics, reverse engineering the algorithms, and blocking the generated domains. However, as a malware developer, our approach needs to evolve. We propose developing a DGA that is fundamentally more dynamic, operating in real-time with unpredictable patterns—let's call this **Flux-DGA**.

## Innovative Methods

To achieve this, two innovative methods are considered:

### Method 1: Leverage Real-Time Data

Leverage real-time data from news websites to generate seeds. News content is inherently random and constantly updated, providing a robust mechanism for generating unique domain names based on the latest articles.

### Method 2: Utilize Blockchain Technology

Utilize blockchain technology. By extracting seeds from variables such as cryptocurrency prices, transaction details, or block characteristics, we can ensure a continuous supply of fresh, hard-to-predict seeds.

Both methods, while still potentially vulnerable to reverse engineering, introduce a new layer of complexity for security researchers. They necessitate internet access, aligning with the needs of most malware which seeks to establish command and control (C2) communications.

## Proof of Concept

This PoC includes:

- Trying to establish a TLS connection with the domain (etherscan.io)
- Reading the contents of the website, to try to get the value of ethereum.
- If the value is retrieved it continues to generate a list of random domains using the dynamic price of ethereum as seed.

## Improvements

**Fail-safe Measures:**

- If the domain etherscan.io is unreachable for any reason, we could maintain a curated list of alternative domains.
- If the domain etherscan.io is modified, we could switch to using domains from the curated list.

There are endless possibilities with Flux-DGA @Pyramidyon.
