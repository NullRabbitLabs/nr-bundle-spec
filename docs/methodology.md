# How the Validator Integrity Index is built

*A companion to the Bundle v1 format specification and the NullRabbit disclosure record.*

NullRabbit Labs measures one thing: the probability that a given blockchain validator or node client
commits a slashable fault or is remotely exploitable. This note explains how the underlying finding
record is built, and just as importantly, what the index does and does not yet claim. A rating layer is
either trusted or it is nothing, so the method and its honest limits are the product.

## 1. Canonicalise, don't count

Adversarial research surfaces the same underlying weakness many times: across chains, across ports, and
across client implementations. Counting each surfacing as a separate finding inflates a number without
adding information. Instead, one written rule collapses repeat surfacings of the same root weakness into a
single canonical record, keyed to the specific client and component. The index therefore measures
distinct, real weaknesses rather than research volume.

## 2. Provenance: ours, or a reproduction of someone else's public disclosure

Every record is marked as one of two kinds. The first is original, meaning a weakness NullRabbit
discovered or first measured. The second is public-replication, meaning a faithful reproduction of an
already-public disclosure such as a CVE, a GHSA advisory, or a named third-party audit. The distinction is
explicit, so that a re-statement of public work is never mistaken for a novel finding, and so the line
between what is disclosure-gated and what is freely publishable is never in doubt.

## 3. One vocabulary for every finding

Every weakness is classified into one of eleven chain-agnostic families defined by the Bundle v1 format:
response amplification, compute amplification, memory amplification, connection exhaustion, consensus
abuse, gossip abuse, authentication bypass, rate-limiter bypass, service misconfiguration, reconnaissance,
and a benign class. The vocabulary is defined by mechanism, not by chain. A finding in a Solana RPC path
and a structurally identical finding in a Cosmos RPC path receive the same family label. That is what
makes cross-client comparison meaningful, and what lets a finding reported by an outside team drop into
the same scheme. The [adoption guide](adoption-guide.md) shows how to classify a finding.

## 4. The disclosure record, including the rejections

For every disclosed finding, NullRabbit records what was sent to the vendor and what the vendor actually
said back. That includes the disclosures that were ignored, dismissed, or declined, and the findings
NullRabbit itself later retracted. This record is published deliberately. Showing where vendors
disagreed, where they went silent, and where we were wrong is precisely what makes the rest of the record
credible.

## 5. What the index does not claim

Honesty about limits is part of the method, not a footnote.

First, the index is procedural, not yet empirical. Today its credibility rests on a clean, documented
method and an honest disclosure record, not on a large body of vendor-confirmed, externally-credited
validations. Those accrue over time as disclosures are acknowledged. Until then, the per-client ratings
are not presented as externally proven.

Second, there is no cross-chain generalisation claim. The research behind the index does not yet reliably
generalise a detector trained on one chain to an unseen chain. That limitation is reported plainly, and
in-distribution results are never presented as cross-chain ones.

Third, self-graded severity is a liability, not an asset. Where a severity is our own assessment rather
than a vendor's, it is treated as provisional and calibrated against the disclosed evidence.

## 6. Scope

The index covers node and client software only: the daemon a validator runs, spanning consensus, RPC,
peer-to-peer, and co-located services. On-chain contract, protocol, and DeFi-economic findings are a
separate measurement with a separate vocabulary, and they are deliberately not folded in.

## Where the standard lives

The Bundle v1 format and the family vocabulary are published under the MIT license in this repository. The
format is designed to be adopted on third-party data without coordination. See the
[adoption guide](adoption-guide.md).
