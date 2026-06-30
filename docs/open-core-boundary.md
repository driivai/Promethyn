# Open-Core Boundary and Commercial Split

Status: draft for adoption
Owner: project maintainers
Applies to: Promethyn open-source repository, hosted services, enterprise deployments, commercial extensions

## 1. One-line principle

The open-source project defines, proves, and tests the Promethyn protocol; the commercial product operates, scales, secures, and supports managed infrastructure around that protocol.

## 2. Purpose

This document defines the boundary between the open-source Promethyn project and any commercial products, hosted services, enterprise features, or private deployments built around it.

The purpose of this boundary is to keep the protocol public, inspectable, and trustworthy while allowing a sustainable business to exist around managed operation, enterprise support, compliance, scale, and specialized deployment.

This boundary is intentional. It should not be inferred from convenience, customer pressure, roadmap urgency, or implementation drift.

## 3. Core rule

Promethyn's open-source repository must contain enough to understand, implement, test, and locally run the protocol — including the safety-critical reference implementations needed to prove the protocol's guarantees without paid infrastructure.

Commercial products may provide hosted infrastructure, managed persistence, advanced operational controls, enterprise integrations, compliance tooling, and supported deployments.

Commercial products must not redefine the protocol in a private fork.

If the commercial system needs a concept that changes the protocol, that concept belongs in the open protocol first.

## 4. Open-source scope

The following belong in the open-source repository.

| Area | Open-source commitment |
| --- | --- |
| Protocol specification | Public protocol docs, architectural decisions, invariants, and conformance requirements |
| Core type system | Public definitions for TaskPacket, Proposal, VerificationRequest, TestPlan, JudgedProposal, Judgment, GateDecision, ExecutionResult, and related protocol types |
| Proposer / judge wall | Type-level contracts that prevent proposer-side objects from reaching execution |
| Verifier interfaces | Public verifier interfaces, verifier result contracts, evidence schemas, and trust-ranking inputs |
| Gate interfaces and reference | Public gate interfaces, decision contracts, held-out firewall requirements, policy routing contracts, and a runnable reference gate-with-firewall sufficient to prove the safety claim |
| Experience ledger interface and raw data | Public ledger interface, a minimal local implementation, and the complete raw event chain it records (packet, proposals, test plan, judgments, gate decisions, execution results, outcomes) |
| Skill registry interface | Public interface for inspectable, versioned, reversible skills |
| Memory interfaces | Public scoped-memory interfaces and local reference implementations |
| Model provider boundary | Public model-provider abstraction so the runtime is model/provider agnostic |
| Swarm proposer layer | Role synthesis, mandatory roles, proposer-side roles, debate selection, and TestPlan generation |
| Local runtime | A reference local runtime that can execute the protocol in development without paid infrastructure |
| Sandbox executor | A safe local/open executor for tests, examples, dry runs, and non-production execution |
| Conformance tests | Public tests proving invariants such as the proposer/judge wall, no verifier forks, no raw proposal execution, and firewall preservation |
| Examples | Minimal examples showing how to use the protocol locally |
| SDKs / CLI | Developer tools required to initialize, run, test, and inspect local protocol behavior |
| Documentation | Public docs for architecture, governance, safety boundaries, extension points, and contribution rules |

## 5. Commercial scope

The following may belong in commercial, hosted, enterprise, or private products.

| Area | Commercial product scope |
| --- | --- |
| Managed verifier bank | Hosted verifier orchestration, persistence, scaling, monitoring, trust calibration, verifier uptime, and operational reliability |
| Managed ledger | Hosted durable event storage, retention controls, query APIs, audit exports, and operational backups |
| Managed skill registry | Hosted versioning, promotion workflows, rollback controls, deployment scopes, and team approval flows |
| Enterprise dashboards | Web interfaces for monitoring, audit, role reputation, verifier performance, gate decisions, and skill promotion |
| Team workspaces | Organization accounts, roles, permissions, team-level governance, and workspace isolation |
| Enterprise authentication | SSO, SCIM, RBAC, audit permissions, and enterprise identity integrations |
| Compliance packs | Prebuilt policies, audit exports, retention profiles, evidence packs, and industry-specific controls |
| Private deployments | Supported self-hosted, VPC, on-prem, or dedicated cloud deployments |
| Premium integrations | Production connectors to CRMs, DMS systems, ticketing systems, code platforms, data warehouses, compliance systems, or enterprise tools |
| Managed human approval | Hosted review queues, escalation policies, approval routing, and decision review workflows |
| Advanced analytics | Role reputation scoring, verifier calibration dashboards, drift detection, outcome analysis, and cost/performance optimization over the open raw data |
| Verifier distribution | Certified verifier distribution, billing, private verifier hosting, verifier SLAs, and enterprise verifier packs — each conforming to the public verifier contract |
| Commercial support | SLA support, onboarding, architecture review, implementation help, custom deployment, and enterprise maintenance |
| Billing and usage controls | Metering, invoices, quotas, usage-based billing, spend controls, and commercial account management |

## 6. Explicit non-boundaries

The following may not be moved into commercial-only code because doing so would weaken the open protocol.

| Must remain open | Reason |
| --- | --- |
| Protocol types | Private protocol types would create incompatible implementations |
| Core invariants | Safety cannot depend on proprietary behavior |
| Conformance tests | The public must be able to test whether an implementation follows the protocol |
| Verifier interface | Verifiers must be portable and independently implementable |
| Verifier conformance | Every verifier that plugs into the bank speaks the public evidence and trust contract |
| Gate decision contract | Execution safety depends on a public, inspectable contract |
| Reference gate and firewall | The safety claim must be runnable and verifiable without paid infrastructure |
| Proposer/judge wall | The core safety boundary must be public and testable |
| Experience ledger raw data | Auditability and analytics fairness require the raw event chain to be open and complete |
| Local sandbox executor | Developers need a safe way to test protocol behavior without commercial infrastructure |
| Reference local runtime | The protocol must be runnable without a hosted service |
| Extension points | Developers must be able to build compatible verifiers, gates, roles, and memory backends |

## 7. Seam resolution: managed vs interface

The open-source project owns interfaces, contracts, schemas, invariants, conformance tests, and a minimal local implementation.

The commercial product may own managed implementations of those interfaces.

This means:

* The VerifierBank interface is open.
* A basic local verifier bank implementation is open.
* The hosted, scaled, monitored, enterprise-grade verifier bank may be commercial.

Likewise:

* The ledger interface is open.
* A local ledger implementation is open.
* A hosted, queryable, retained, compliant audit ledger may be commercial.

Commercial features may improve reliability, scale, security, and operations. They may not replace public protocol contracts with private-only contracts.

## 8. Seam resolution: custom verifiers

"Custom verifiers" does not mean the verifier system itself is private.

The verifier interface, evidence contract, trust-ranking inputs, and conformance requirements remain open.

Any verifier that plugs into the verifier bank conforms to the public evidence and trust-ranking contract. "Private," "custom," or "enterprise" describes a verifier whose implementation, hosting, distribution, and access are commercial — it never describes a verifier that speaks a private protocol. Verifiers are the protocol's master key; a verifier that does not conform to the public contract is a private protocol fork at the most sensitive point, and is not permitted.

Commercial custom-verifier offerings may include:

* Building conformant verifier implementations for a customer.
* Hosting private verifiers.
* Certifying third-party verifiers against the public contract.
* Maintaining production verifier integrations.
* Providing verifier SLAs.
* Supplying industry-specific verifier packs.
* Operating managed verifier pipelines.

The protocol remains open. The implementation, hosting, support, certification, and private integrations may be commercial. The contract a verifier speaks may not be.

## 9. Seam resolution: data vs analytics

The experience ledger interface and a local implementation are open, and the raw event chain the ledger records is open and complete: the full sequence of task packet, proposals, test plan, judgments, gate decisions, execution results, and outcomes.

Commercial products may host that ledger and may build analysis on top of it — role reputation scoring, verifier calibration dashboards, drift detection, outcome analysis, and cost or performance optimization.

The open ledger must not be deliberately reduced in fidelity to force analytics into commercial-only products. The raw data stays open and complete; the analysis, scoring, and presentation over it may be commercial. Open data, paid insight.

## 10. Seam resolution: reference gate and firewall

The gate is half of the trusted core. Its decision contract, its held-out firewall requirements, and a runnable reference gate-with-firewall implementation are open, so the protocol's central safety claim — that nothing reaches execution without being verified and gated, and that the skill proposer never sees the held-out set — can be inspected and proven by anyone without paid infrastructure.

Commercial products may provide:

* Policy tuning and threshold management.
* Enterprise routing and approval workflows.
* Managed operation, monitoring, and scaling of the gate.

Commercial gate features may not replace the public decision contract or weaken the firewall semantics. A safety guarantee that can only be verified inside a paid product is not a guarantee; the open reference exists precisely so the claim does not reduce to "trust us." This seam is bound by Section 16 (no private safety fork).

## 11. Seam resolution: open sandbox executor

The open-source project must include a sandbox executor.

The sandbox executor exists so developers can test the protocol locally and prove that gated decisions execute while raw proposals and unapproved test plans do not.

The sandbox executor should support:

* Dry-run execution.
* Local test execution.
* Mock tool execution.
* Conformance testing.
* Example workflows.
* Audit-chain generation.

The sandbox executor is not required to provide:

* Production credentials.
* Enterprise tool connectors.
* SLA-backed execution.
* Hosted queues.
* Production scaling.
* External customer messaging.
* Regulated workflow execution.
* Managed human approval.

Production executors for commercial systems may be commercial, but the open-source project must preserve a safe local executor so the protocol remains runnable and testable without paid infrastructure.

## 12. License position

The intended open-source license for the public protocol, SDKs, local runtime, conformance tests, and reference implementations is Apache License 2.0.

Apache-2.0 is intended to support broad adoption, commercial use, enterprise review, and ecosystem development while preserving copyright and patent grant terms under the license.

Commercial cloud services, hosted infrastructure, enterprise dashboards, managed deployments, premium integrations, and support services may be proprietary unless explicitly released under the open-source license.

This document is not legal advice. License structure, contribution terms, and commercial boundaries should be reviewed by qualified counsel before public launch or commercial sale.

## 13. Name, trademark, and conformance mark

Apache-2.0 governs the code. It does not govern the name.

Because a permissive license permits anyone to fork and modify the protocol code — including in ways that weaken its safety semantics — copyright is not the lever that protects the protocol's integrity. The project name and conformance mark are.

* The project name "Promethyn," and any associated logos and marks, are trademarks of the project maintainers and are not licensed under Apache-2.0.
* A conformance designation (for example, "Promethyn-compatible" or "Promethyn-certified") may be used only by an implementation that passes the public conformance tests at a stated protocol version.
* Apache-2.0 permits forking and modifying the code; it does not grant the right to use the project name or the conformance mark. A fork that alters the protocol or weakens the safety semantics may not represent itself as Promethyn or as conformant.

This is the enforcement mechanism for an open protocol. The conformance tests define what conformance means; the name and mark are reserved to implementations that earn it. A fork is free to exist; it is not free to claim the name while diverging from the protocol it names.

Trademark registration and the conformance-mark policy should be reviewed by qualified counsel. This is not legal advice.

## 14. Contributor License Agreement

Contributions to the open-source project require a Contributor License Agreement.

The CLA exists to make the open/commercial split legally real and operationally safe. It allows the project maintainers to accept community contributions while preserving the ability to:

* Maintain the open-source project.
* Offer hosted commercial services.
* Provide enterprise deployments.
* Dual-license where needed.
* Defend the project's legal rights.
* Keep the public protocol stable and commercially sustainable.

The CLA grant may not be used to remove from public availability any of the following, which remain permanently open and inspectable:

* The protocol contracts and types.
* The core invariants.
* The conformance tests.
* The reference safety implementations: the proposer/judge wall, the reference gate and held-out firewall, the sandbox executor, the local verifier bank, and the local ledger with its raw event chain.

Dual-licensing and commercial services apply to managed operation, hosting, scale, and enterprise features — never to closing the protocol or its safety core. A CLA that could close the safety core would deter exactly the safety-minded contributors the project most wants; this clause is intended to be ironclad and should be drafted by counsel to be so.

## 15. Contribution requirements

Acceptance of a contribution into the open-source repository is conditional on passing two public gates, in addition to maintainer review:

* Conformance gate. No contribution may introduce a duplicate verifier, gate, ledger, or execution authority; a private protocol dependency; or a change to the meaning of verification, gating, promotion, rollback, execution authorization, or auditability — except as an explicitly approved protocol change.
* Hygiene gate. All committed artifacts and contribution metadata remain vendor-neutral per the project's hygiene policy. This standard applies to every contributed surface, including text authored outside automated checks — pull request descriptions, release notes, wiki pages, and documentation — which must be kept clean by the contributor and the maintainers.

Making these gates a condition of acceptance, rather than a matter of style, binds the project's standards into the contribution contract and keeps the public protocol surface consistent and trustworthy.

## 16. No private safety fork

Commercial products must not create a private safety model that contradicts the open-source safety model.

If a commercial feature improves the verifier bank, gate, proposer/judge wall, ledger contract, firewall, or promotion rules in a way that changes the protocol's safety semantics, the protocol-level change must be proposed publicly.

Commercial products may add:

* Managed operation.
* Better scale.
* Enterprise controls.
* Private integrations.
* More dashboards.
* More deployment options.
* More support.
* More compliance packaging.

Commercial products may not silently redefine what counts as verified, gated, executable, or promotable.

## 17. Decision rule for future features

When a new feature is proposed, classify it using this rule:

If the feature is necessary to understand, implement, test, or trust the protocol, it belongs in open source.

If the feature is necessary to operate, scale, secure, monitor, customize, or commercially support the protocol in production, it may belong in the commercial product.

If the feature changes the meaning of verification, gating, promotion, rollback, execution authorization, or auditability, it must be treated as protocol-level and reviewed for open-source inclusion.

## 18. Examples

Open-source

* TaskPacket schema
* Proposal schema
* VerificationRequest schema
* TestPlan schema
* Judgment contract
* GateDecision contract
* Local verifier bank
* Local memory store
* Local ledger and its raw event chain
* Reference gate and held-out firewall
* Sandbox executor
* Swarm role synthesis
* Debate layer that emits TestPlan
* Conformance tests for proposer/judge separation
* CLI for local runs
* Protocol documentation

Commercial

* Hosted verifier bank
* Enterprise ledger retention
* SOC 2 evidence exports
* Private verifier hosting (conformant)
* CRM production connector
* Enterprise dashboard
* Team approval queues
* SSO / SCIM
* Advanced role reputation analytics
* Usage metering
* Dedicated cloud deployment
* Paid support
* Industry compliance packs

## 19. Enforcement

This boundary should be enforced through:

* Repository structure.
* Public interfaces.
* Conformance tests, and the conformance mark that depends on them.
* The trademark and conformance-mark policy.
* The hygiene and conformance gates in continuous integration.
* Governance review.
* CLA process.
* Release review.
* Architectural decision records.
* Documentation updates.

Any pull request that introduces a duplicate verifier, duplicate gate, duplicate ledger, duplicate execution authority, a non-conformant verifier, or a private protocol dependency should be rejected unless it is explicitly approved as a protocol change.

## 20. Final principle

Promethyn should be open where trust is created and commercial where trust is operated.
