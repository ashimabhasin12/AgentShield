# AgentShield

**Knowledge-Based Runtime Security for Autonomous AI Agents**

AgentShield is a research-oriented security framework designed to enforce human-defined declarative security policies on autonomous AI agents. It evaluates proposed tool calls before execution to prevent unauthorized actions while preserving legitimate task completion.

## Research Question

Can human-defined declarative security policies reduce indirect prompt injection attack success in autonomous AI agents while preserving legitimate task completion, compared with instruction-based and existing defenses?

## Research Objectives

- Investigate external knowledge-based security enforcement.
- Evaluate protection against indirect prompt injection.
- Measure the trade-off between security and legitimate task completion.
- Compare declarative policy enforcement with existing defense mechanisms.
- Evaluate enforcement across different language model sizes.

## Core Features

- Declarative knowledge representation using JSON.
- Default-deny policy enforcement.
- Role-based access control.
- Task-scoped authorization.
- Dynamic permission management.
- Resource and data sensitivity classification.
- Human approval mechanisms.
- Security audit logging.
- Interactive AgentDojo benchmark integration.
- Comparative experimental evaluation.

## System Architecture

AgentShield introduces an external authorization layer between the language model and the tool execution environment.

The language model proposes a tool call. The policy engine evaluates the requested action, resource, data sensitivity, task scope and authorization requirements before allowing execution.

The framework produces three possible decisions:

| Decision | Description |
|---|---|
| ALLOW | Execute an authorized action. |
| BLOCK | Prevent a restricted or unauthorized action. |
| REVIEW | Require approval before execution. |

The authorization decision is enforced independently of the language model.

## Knowledge Representation and Security Policies

Security knowledge is represented through structured JSON policies and task-specific authorization manifests.

| Policy ID | Security rule | Decision |
|---|---|---|
| P001 | Restrict destructive deletion operations | BLOCK |
| P002 | Protect confidential information | BLOCK |
| P003 | Permit authorized information retrieval | ALLOW |
| P004 | Require approval for authorized external communications | REVIEW |
| P005 | Prevent actions outside the authorized task scope | BLOCK |
| P006 | Permit authorized internal operations | ALLOW |

The framework incorporates least privilege, confidentiality, default-deny authorization and human oversight.

## Technologies

| Technology | Purpose |
|---|---|
| Python | Core framework and experimental implementation |
| AgentDojo | Interactive security benchmark |
| AgentDojo v1.2.2 | Benchmark suite version |
| Groq | Cloud-based model inference |
| Ollama | Local model experimentation |
| GPT-OSS-20B | Experimental language model |
| GPT-OSS-120B | Experimental language model |
| JSON | Declarative security knowledge representation |
| SQLite | Application database and audit logging |
| HTML, CSS and JavaScript | Prototype user interface |

## Experimental Methodology

Experiments are conducted within AgentDojo's interactive execution environment rather than through static dataset classification.

The evaluation uses AgentDojo's built-in utility and security checks under benign and adversarial conditions.

Development and preliminary holdout tasks are separated to reduce benchmark-specific policy tuning. A frozen policy configuration, recorded policy hashes and a fixed random seed of 42 support experimental consistency.

## Models Tested

| Model | Research purpose |
|---|---|
| GPT-OSS-20B | Preliminary development and holdout evaluation |
| GPT-OSS-120B | Comparative benign and adversarial development evaluation |

Both models belong to the same model family. Cross-family generalizability has not yet been established.

## Comparison Baselines

| Configuration | Defense mechanism |
|---|---|
| B1 | Unprotected AI agent |
| B2 | Natural-language safety instructions |
| B3 | AgentDojo repeat-user-prompt defense |
| B4 | AgentDojo tool-filtering defense |
| Proposed approach | AgentShield runtime policy enforcement |

## Evaluation Metrics

| Metric | Description |
|---|---|
| Benign Utility | Legitimate task completion without attacks |
| Attacked Utility | Legitimate task completion under adversarial conditions |
| Attack Success Rate | Completed adversarial runs satisfying the attack objective |
| Block Rate | Proportion of proposed tool calls blocked |
| Human Review Rate | Proportion of proposed tool calls referred for approval |
| Legitimate Task Failure | Proportion of legitimate tasks not successfully completed |

## Preliminary Experimental Results

### GPT-OSS-120B — Development Evaluation

| Defense | Benign Utility | Attacked Utility | Attack Success Rate |
|---|---:|---:|---:|
| Unprotected agent | 100% | 33.3% | 66.7% |
| Safety instructions | 100% | 66.7% | 33.3% |
| Repeat user prompt | 100% | 100% | 0% |
| Tool filtering | 0% | 0% | 0% |
| AgentShield | 100% | 100% | 0% |

Thirty development runs were completed across five configurations, three tasks and two experimental conditions.

### GPT-OSS-20B — Development Evaluation

| Defense | Benign Utility |
|---|---:|
| Unprotected agent | 100% (3/3) |
| Safety instructions | 100% (3/3) |
| Repeat user prompt | 100% (3/3) |
| Tool filtering | 0% (0/3) |
| AgentShield | 66.7% (2/3) |

### GPT-OSS-20B — Additional Holdout Defense Evaluation

| Defense | Completed Runs | Attacked Utility | Attack Success Rate |
|---|---:|---:|---:|
| Repeat user prompt | 5/6 | 40% | 20% |
| Tool filtering | 5/6 | 0% | 0% |

Ten of the twelve planned additional defense runs were completed. Two runs remain pending due to API rate limitations.

### Matched Preliminary Holdout Comparison

| Configuration | Benign Utility | Attacked Utility | Attack Success Rate |
|---|---:|---:|---:|
| Unprotected agent | 60% (3/5) | 66.7% (2/3) | 0% (0/3) |
| AgentShield | 40% (2/5) | 66.7% (2/3) | 0% (0/3) |

These results use matched completed tasks from an earlier frozen-policy evaluation. They are reported separately because experimental configurations and completion counts differ.

### Runtime Authorization Statistics — GPT-OSS-120B

| Decision | Benign Condition | Adversarial Condition |
|---|---:|---:|
| ALLOW | 5 | 5 |
| BLOCK | 4 | 7 |
| REVIEW | 1 | 1 |
| Total tool calls | 10 | 13 |

Human approval was simulated during benchmark experiments. Blocked tool calls have not yet been individually classified as legitimate or malicious.

## Preliminary Findings

AgentShield demonstrated better observed security and utility outcomes than natural-language safety instructions alone on the GPT-OSS-120B development sample.

It matched the repeat-user-prompt defense while achieving higher legitimate task utility than restrictive tool filtering.

Earlier holdout experiments identified limitations in legitimate task completion, demonstrating the importance of balancing security enforcement with task utility.

These findings are preliminary and do not establish generalizable superiority over existing defenses.

## Repository Structure

| File or directory | Purpose |
|---|---|
| `research_policies.json` | Declarative research security rules |
| `research_policy_engine.py` | Policy evaluation and reasoning |
| `research_secure_runtime.py` | Runtime authorization enforcement |
| `task_permission_engine.py` | Task-specific authorization |
| `dynamic_permission_engine.py` | Dynamic permission management |
| `agentdojo_environment.py` | Benchmark environment integration |
| `experiments/` | Comparative experimental scripts |
| `policies/` | Security policies and authorization manifests |
| `research_results/` | Selected preliminary metrics and research documentation |
| `live_app.py` | Live application prototype |
| `web_app.py` | Web-based demonstration |

## Experiment Scripts

The following scripts support the preliminary experimental evaluation:

- `experiments/second_model_benign.py`
- `experiments/second_model_attack.py`
- `experiments/resume_defense_attacks.py`

Experimental execution requires the appropriate Python dependencies, AgentDojo benchmark configuration and authorized API access.

API credentials must be configured locally and must never be committed to the repository.

## Related Research

| Research | Relevance |
|---|---|
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Interactive benchmark for evaluating prompt injection attacks and defenses |
| [Progent](https://arxiv.org/abs/2504.11703) | Programmable privilege enforcement for LLM agents |
| [CaMeL](https://arxiv.org/abs/2503.18813) | Capability-based security and separation of trusted control from untrusted data |
| [NIST SP 800-162](https://doi.org/10.6028/NIST.SP.800-162) | Attribute-based access control principles |

The comparison with Progent and CaMeL is currently literature-based rather than a direct experimental comparison.

## Research Limitations

- Small preliminary experimental sample.
- Two pending defense experiments due to API restrictions.
- Simulated human approval.
- Evaluation using models from the same model family.
- Incomplete adversarial payload exposure verification.
- Potential restrictions on legitimate tool calls.
- Further validation of holdout independence and reproducibility required.

## Research Status

The research framework has been implemented, and preliminary benign and adversarial experiments have been conducted.

The current research is undergoing methodological validation and academic review in preparation for potential journal publication.

## Researcher

**Ashima Bhasin**

Bachelor of Computing Science  
Thompson Rivers University  
Kamloops, British Columbia, Canada

## Acknowledgments

The research is being developed with academic guidance from Dr. Sukhchandan at Thompson Rivers University.

## Disclaimer

AgentShield is an experimental academic research framework. Its current results should not be interpreted as a guarantee of security in production environments.
