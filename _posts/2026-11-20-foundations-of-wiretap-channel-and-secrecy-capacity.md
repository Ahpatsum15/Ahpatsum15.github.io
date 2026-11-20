---
layout: post
title: "Foundations of the Wiretap Channel and Secrecy Capacity: From Wyner to Quantum Information"
date: 2026-11-20
categories:
  - information-theory
tags:
  - information-theory
  - phd
  - quantum-information
  - cryptography
  - secrecy-capacity
author: Mustapha El Bouazaoui
---

## 1. Introduction: Computational vs. Information-Theoretic Security

In modern cryptography, security proofs typically rely on computational hardness assumptions—such as the discrete logarithm problem, prime factorization, or the hardness of lattice-based learning with errors (LWE). While these assumptions protect everyday communication against polynomially bounded adversaries, they remain inherently vulnerable to algorithmic breakthroughs, side-channel attacks, or the eventual realization of large-scale fault-tolerant quantum computers running Shor's algorithm.

**Information-theoretic security**, originally formulated by Claude Shannon in his seminal 1949 paper *"Communication Theory of Secrecy Systems"*, adopts a fundamentally different perspective. Instead of relying on an adversary's computational limitations, information-theoretic security guarantees that the adversary's intercepted transmission reveals **zero statistical information** about the plaintext message, regardless of computing power.

Shannon established that perfect secrecy requires:

$$H(M \mid C) = H(M) \iff I(M; C) = 0$$

where $M$ denotes the plaintext message, $C$ the ciphertext, $H(\cdot)$ is Shannon entropy, and $I(\cdot ; \cdot)$ is mutual information. The fundamental price for Shannon's perfect secrecy is that the secret key entropy must equal or exceed the message entropy:

$$H(K) \ge H(M)$$

This requirement explains why the one-time pad (OTP) remains impractical for high-throughput communications without pre-shared keys of equivalent size.

However, in 1975, **Aaron D. Wyner** demonstrated a profound breakthrough: by exploiting the physical imperfections and noise inherent to transmission media, two parties can establish confidential communication and generate shared secrecy **without any pre-shared secret key**. This framework is known as the **Wiretap Channel**, and it serves as the foundational starting point for my doctoral dissertation at UM6P College of Computing.

---

## 2. Wyner's Degraded Wiretap Channel Model

Consider three canonical agents:
- **Alice (Transmitter)**: Wants to send a confidential message $W \in \{1, 2, \dots, M\}$ to Bob.
- **Bob (Legitimate Receiver)**: Observes channel output $Y^n \in \mathcal{Y}^n$.
- **Eve (Wiretapper/Eavesdropper)**: Observes wiretap output $Z^n \in \mathcal{Z}^n$.

```
         +-------+     X^n     +-----------------+     Y^n     +-------+
Message -| Alice |------------>|  Main Channel   |------------>|  Bob  |-> \hat{W}
   W     +-------+             |  P(y|x)         |             +-------+
                               +-----------------+
                                        |
                                        v
                               +-----------------+     Z^n     +-------+
                               | Wiretap Channel |------------>|  Eve  |-> Equivocation
                               | P(z|y)          |             +-------+
                               +-----------------+
```

In Wyner's degraded formulation, the joint transition probability factorizes according to the Markov chain:

$$X \longrightarrow Y \longrightarrow Z$$

This implies:

$$P(y, z \mid x) = P(y \mid x) P(z \mid y)$$

### Secrecy Criteria and Equivocation

A transmission scheme is characterized by a codebook with block length $n$ and message transmission rate:

$$R = \frac{1}{n} \log_2 M$$

The legitimate receiver must reconstruct the message with arbitrarily low probability of error:

$$\lim_{n \to \infty} P_e^{(n)} = \lim_{n \to \infty} \Pr\{\hat{W} \neq W\} = 0$$

To quantify Eve's uncertainty, Wyner defined the **equivocation rate**:

$$\Delta = \frac{1}{n} H(W \mid Z^n)$$

Under the **strong secrecy criterion**, the mutual information between the transmitted message $W$ and Eve's observations $Z^n$ must vanish asymptotically:

$$\lim_{n \to \infty} I(W; Z^n) = 0$$

---

## 3. The Secrecy Capacity Theorem

The **secrecy capacity** $C_s$ is the maximum transmission rate at which information can be delivered reliably to Bob while guaranteeing asymptotic secrecy with respect to Eve.

### Wyner's Degraded Wiretap Capacity

For the degraded wiretap channel where $X \to Y \to Z$, Wyner proved that:

$$C_s = \max_{p(x)} \left[ I(X; Y) - I(X; Z) \right]$$

### Csiszár and Körner's Generalization (1978)

For arbitrary (non-degraded) broadcast channels with confidential messages, Imre Csiszár and János Körner proved the generalized capacity formula introducing an auxiliary random variable $U$:

$$C_s = \max_{p(u, x)} \left[ I(U; Y) - I(U; Z) \right]^+$$

where $[a]^+ = \max(0, a)$, and the random variables satisfy the Markov condition $U \to X \to (Y, Z)$.

> **Core Intuition**: Secrecy capacity is strictly positive ($C_s > 0$) whenever Bob's channel quality is statistically superior to Eve's channel quality. Alice utilizes stochastic encoding (random binning) to inject artificial noise into Eve's decoder while Bob retains sufficient mutual information to decode deterministically.

---

## 4. The Gaussian Wiretap Channel

To see this in practical communication systems, consider the additive white Gaussian noise (AWGN) wiretap channel:

$$Y = X + N_B, \quad N_B \sim \mathcal{N}(0, \sigma_B^2)$$

$$Z = X + N_E, \quad N_E \sim \mathcal{N}(0, \sigma_E^2)$$

under average transmitter power constraint $\mathbb{E}[X^2] \le P$.

The capacity of Bob's channel and Eve's channel are respectively:

$$C_B = \frac{1}{2} \log_2\left(1 + \frac{P}{\sigma_B^2}\right), \quad C_E = \frac{1}{2} \log_2\left(1 + \frac{P}{\sigma_E^2}\right)$$

The Gaussian secrecy capacity evaluates to:

$$C_s = \left[ C_B - C_E \right]^+ = \begin{cases} \frac{1}{2} \log_2\left(\frac{1 + P/\sigma_B^2}{1 + P/\sigma_E^2}\right), & \text{if } \sigma_B^2 < \sigma_E^2 \\ 0, & \text{if } \sigma_B^2 \ge \sigma_E^2 \end{cases}$$

```
Secrecy Capacity (bits/channel use)
   ^
   |        .-------------------  High SNR asymptote: log2(sigma_E / sigma_B)
   |       /
Cs |      /
   |     /
   |    /
   +---+------------------------> Transmitter Power P
```

---

## 5. From Classical to Quantum Wiretap Channels: The PhD Frontier

In modern physical implementations—including deep-space satellite optical links, fiber-optic telecom backbones, and quantum key distribution (QKD) infrastructures—signals propagate as single photons or coherent quantum states.

In a **Quantum Wiretap Channel**, Alice encodes classical messages into quantum density matrices $\rho \in \mathcal{S}(\mathcal{H}_A)$. The transmission medium is described by a completely positive trace-preserving (CPTP) quantum channel:

$$\mathcal{N} : \mathcal{B}(\mathcal{H}_A) \longrightarrow \mathcal{B}(\mathcal{H}_B)$$

Because every quantum channel admits an isometric Stinespring dilation $U : \mathcal{H}_A \to \mathcal{H}_B \otimes \mathcal{H}_E$, whatever information is lost to the environment is accessible to Eve through the complementary channel $\mathcal{N}^c$:

$$\mathcal{N}^c : \mathcal{B}(\mathcal{H}_A) \longrightarrow \mathcal{B}(\mathcal{H}_E)$$

### Private Classical Capacity $C_p(\mathcal{N})$

The rate at which Alice can transmit secret classical data over a quantum channel while keeping Eve completely decoupled in trace distance:

$$\lim_{n \to \infty} \left\| \rho_{W E^n} - \rho_W \otimes \rho_{E^n} \right\|_1 = 0$$

is governed by the **Holevo information** $\chi$:

$$\chi(\{p_x, \rho_x\}) = S\left(\sum_x p_x \rho_x\right) - \sum_x p_x S(\rho_x)$$

where $S(\rho) = -\mathrm{Tr}(\rho \log_2 \rho)$ is the von Neumann entropy.

The regularized private capacity is expressed by:

$$C_p(\mathcal{N}) = \lim_{n \to \infty} \frac{1}{n} \max_{\{p_x, \rho_x\}} \left[ \chi(\{p_x, \mathcal{N}^{\otimes n}(\rho_x)\}) - \chi(\{p_x, (\mathcal{N}^c)^{\otimes n}(\rho_x)\}) \right]$$

### Research Focus at UM6P

Unlike classical memoryless channels where single-letter formulas suffice, quantum channels can exhibit **superadditivity**, where $C_p(\mathcal{N}^{\otimes 2}) > 2 C_p(\mathcal{N})$.

My research focuses on:
1. **Explicit Secrecy Bounds**: Deriving non-asymptotic bounds for noisy bosonic and depolarizing wiretap models.
2. **Polar & LDPC Coding**: Designing practical error-correction and privacy-amplification codes that approach the secrecy capacity without requiring impractically large quantum blocklengths.
3. **Finite-Blocklength Analysis**: Investigating error-exponent behavior and second-order asymptotics under realistic SNR fluctuations.

---

## 6. What's Next in This Series

This article forms the theoretical foundation for upcoming articles in my PhD research companion series:
- **Part 2**: *Strong Secrecy vs. Weak Secrecy: Random Binning and Information-Spectrum Methods*
- **Part 3**: *Coding for the Gaussian Wiretap Channel with Polar Codes*
- **Part 4**: *Complementary Channels, Dilation Theory, and Quantum Secrecy Capacity*

Stay tuned for derivations, Jupyter simulation notebooks, and code implementations!
