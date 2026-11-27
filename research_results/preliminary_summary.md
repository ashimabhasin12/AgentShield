# AgentShield - Preliminary Research Summary

## Objective
Evaluate human-defined runtime security policies
against indirect prompt injection attacks.

## Methodology
AgentDojo v1.2.2, GPT-OSS-20B, declarative policies,
default-deny enforcement and simulated human approval.

## Preliminary Results
Development utility:
- Baseline: 100%
- Safety Instructions: 100%
- Repeat User Prompt: 100%
- AgentShield: 66.7%
- Tool Filter: 0%

Matched holdout utility without attacks:
- Baseline: 60%
- AgentShield: 40%

Matched utility under attack:
- Baseline: 66.7%
- AgentShield: 66.7%

Recorded attack exposure:
- Baseline: 0 successful attacks out of 3
- AgentShield: 0 successful attacks out of 2

## Overfitting Prevention
Six candidate holdout tasks selected using seed 42.
No overlap with the documented development tasks.
Four frozen policy file hashes verified.

## Limitations
Small sample size, incomplete attack experiments,
API quota restrictions and simulated human approval.
Security superiority has not yet been established.

## Related Work
Progent and CaMeL provide external security enforcement.
AgentShield investigates human-defined authorization
and the associated security-utility trade-offs.
