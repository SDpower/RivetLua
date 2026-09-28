# RivetLua Project Guidance

## Scope and Instruction Priority

- This file supplements the applicable global guidance for work in RivetLua. Higher-priority system, developer, and user instructions continue to take precedence; this file does not override them.
- For this project, the following project-specific workflow rules take precedence over conflicting general workflow guidance: the permitted implementation-agent roles and their selection; one delegation for a bounded sequence of already-defined steps; a complete initial brief followed by incremental updates; evidence-based reuse of valid verification results; and concise intermediate reports.
- This file does not prescribe the primary agent's model or change global agent settings.
- Agent selection, delegation, and coordination are responsibilities of the primary agent. An implementation agent must not delegate further unless the primary agent explicitly instructs it. Agents execute the agreed task; they do not re-plan it, expand its scope, or make unauthorized architectural decisions.
- This file is written in English at the user's direction. User-facing replies, code comments, and commit messages should otherwise be in Traditional Chinese. Project documentation under `docs/` should be in Traditional Chinese. Commit only when the user explicitly requests it.
- Do not create files in the project root unless the user explicitly requests them. Preserve unrelated existing changes and avoid unrelated refactoring, dependency upgrades, toolchain changes, or repository-wide formatting.

## Project Purpose and Sources of Truth

- RivetLua is an independent, general-purpose, embeddable Lua compiler and VM implemented in pure Rust. Do not make requirements of a particular host application or language intelligence system core dependencies.
- Do not replace the core compiler or VM with an external Lua runtime, a C implementation wrapper, or an FFI adapter. This does not prohibit embedding APIs, bindings, or a reference interpreter for tests when authorized by the established plan.
- Use the user-approved plan and project specifications for the target Lua version, compatibility scope, architecture, and verification commands. Inspect only the documentation, code, tests, and build configuration needed for the current task.
- Do not assume the Lua version, crate names, directory layout, GC algorithm, stack representation, or bytecode format. Confirm language behavior, bytecode compatibility, and C API/ABI compatibility separately; none implies the others.
- Existing code and tests are evidence of current behavior, not automatically the specification. Report conflicts to the primary agent; do not redefine requirements by changing tests.

## Implementation-Agent Roles

| Agent | Suitable work | Selection rule |
| --- | --- | --- |
| `plan_implementer` | Bounded general implementation, tests, or documentation with established patterns and local acceptance criteria | Default choice; do not escalate solely because the project is a compiler. |
| `complex_implementer` | Deeply coupled general work outside VM-core semantics, such as high-risk build, tooling, or test infrastructure | Choose based on actual reasoning complexity and regression risk. |
| `vm_core_implementer` | Complex work requiring joint reasoning about compiler, bytecode, closures/upvalues, frames/stacks, coroutines, GC, or related core contracts, state, or lifecycles | Prefer directly when the task meets this description; do not first try a less suitable agent. |

- Choose based on semantic coupling, reasoning demands, and regression risk, not keywords, programming language, or file count. A task need not involve every listed subsystem to qualify as VM-core work.
- For example, adding a closure test to an established specification can use `plan_implementer`; changing upvalue closing together with frame exit, error cleanup, or GC reachability belongs with `vm_core_implementer`.
- The primary agent retains architectural decision-making. Resolve missing requirements, acceptance criteria, or design decisions as blockers; do not ask an agent to guess or use a stronger model as a substitute for a specification.
- Keep an indivisible VM-core contract and its necessary tests and related fixes with one `vm_core_implementer`. Do not split that contract across agents or assign another agent to duplicate the same work.
- If a required agent is unavailable, report the actual error and blocker. Do not silently substitute an agent, reduce the required configuration, or bypass delegation by doing the implementation in the primary agent.

## Planning, Delegation, and Scope

- Read the complete source plan before implementation. State its steps to the user in their original order, then perform them in that order. Do not skip, reorder, or merge plan steps without user authorization.
- Split work into bounded, independently reviewable tasks before delegating. Do not delegate an entire unsplit project plan in one call. A bounded task may contain multiple consecutive plan steps when their dependencies, scope, implementation direction, and acceptance criteria are already defined.
- A delegation brief must identify the selected agent and reason, plan source and steps, objective, allowed files or symbols, necessary read-only references, prerequisites, acceptance criteria, verification commands, and report format. For core work, also include the relevant Lua version or specification, established design, invariants, and cross-layer interfaces to preserve.
- Make the initial brief self-contained and limited to relevant context; do not require an agent to reread the whole repository. For follow-up work in the same agent thread, provide only new goals, changed conditions, and necessary state. A new agent or controlled handoff needs a self-contained brief.
- A single agent may execute a fully specified bounded sequence in one delegation, following every plan step in order and recording each step's outcome. This does not permit skipping, reordering, or combining plan steps, nor does it mean delegating the whole unsplit plan. Do not require a new delegation for every step. Pause only at a required approval point, a specification conflict, a proposed change to scope, architecture, acceptance criteria, or plan order, or a blocker that prevents safe progress.
- Provide concise progress updates that state completed steps, key results, and what comes next; report blockers with the specific decision or information needed. Recording progress for each step does not require a separate tool or agent call per step.
- The authorized write scope must include necessary related changes and tests, but must not default to the whole repository. If work requires reading or editing outside the agreed boundary, the agent must first report the smallest necessary expansion and wait for direction.
- The primary agent may resolve local details within the approved scope. Changes to the user's approved scope, acceptance criteria, architecture, or plan order require user authorization.

## Dependencies, Parallel Work, and Handoffs

- Keep work with ordering dependencies, shared outputs, coupled contracts, or overlapping files or symbols in one agent thread. Test-first TDD and implementation that depends on its result must remain sequential in the same thread.
- Before delegating a dependent sequence, select an agent suited to its most demanding required step. Execute the steps in order within that thread while preserving each step's result.
- Parallelize only tasks without ordering dependencies, shared outputs, coupled contract changes, or overlapping write scope. Different files alone do not make core-contract work independent.
- One bounded task may use one agent. There is no minimum number of agents and no requirement to use every role.
- For an agent-type change in a dependent sequence, use a controlled handoff: wait for or stop the current agent, confirm it has stopped writing, inspect its diff and verification results, then transfer the remaining work and exclusive write ownership. Keep the original plan order and acceptance criteria. Record why the handoff is needed.
- After parallel work completes, the primary agent must inspect the combined diff, integrate changes, resolve conflicts, and complete any remaining overall acceptance checks.

## Core Quality and Verification

- For core changes, the implementation agent must identify the applicable contracts, invariants, and state transitions, then trace relevant normal paths, error cleanup, and necessary cross-layer interactions. Do not turn a bounded task into a full-system audit without cause.
- Do not pass acceptance by disabling GC, leaking memory, retaining objects that should be collectible, weakening assertions or tests, or hiding errors. Any addition or expansion of `unsafe` requires explicit authorization, a safety rationale, and supporting verification.
- Establish the smallest relevant baseline before changing code. For a bug fix, create or identify a minimal reproducer and regression test; for a feature, add tests tied to the specification. Expected output and error behavior must be checkable. Inspect coherent, verifiable units as they become ready; do not run a full test suite after every edit.
- Documentation-only changes require content and diff review; do not run runtime tests automatically for them. Run the checks specified by the plan and any other verification justified by the changed behavior and risk.
- **Basic tests** cover the feature's normal path, boundaries, error behavior, and minimal regression cases.
- **Complete tests** cover the relevant cross-module interactions, state transitions, lifecycles, Lua compatibility behavior, and regressions within the task's acceptance scope. The plan defines that scope. Do not assume Complete tests mean the full workspace at every step, and do not omit explicitly required complete verification.
- Confirm verification commands, working directory, test targets, features, and platform settings from the plan and build environment. Do not guess crate names, test names, toolchains, or supported platforms.
- Differential tests, GC stress tests, Miri, and sanitizers are appropriate only when relevant and already available or explicitly authorized. If required facilities are unavailable, report the limitation; do not install tools or expand the toolchain on your own.
- Keep one concise verification record with the actual command, relevant environment or configuration, target or test count, outcome, and code state tested. Distinguish passed, failed, not run, and blocked checks. Zero matching tests is not a pass; compilation alone is not a test pass.
- A verification result applies only to the tested code, dependencies, test content, build settings, and relevant environment. If a later change affects any of them, rerun the affected checks. Reuse a result when evidence shows those inputs remain unchanged, and state the basis. If impact cannot be determined reliably, broaden verification. Never use an old result to claim that affected later changes passed.
- The implementation agent owns complete task-level implementation, local diff review, and required verification. The primary agent owns final review of the integrated diff and coverage, and must complete plan-required overall acceptance. It may rely on an agent's result when that result covers the same final relevant state; it should verify integration changes, cross-task interactions, and uncovered acceptance criteria. Do not rerun a check solely because a different agent ran it.
- Do not repeat expensive verification or retry blindly when no new evidence justifies it. Do not omit required acceptance checks to save time or tokens.

## Tool-Call and Context Efficiency

- Each tool or agent call must have a clear purpose: obtain missing evidence, complete a bounded change, test a specific assumption, verify a required condition, or resolve a blocker. When sufficient evidence is available, proceed without calls that add no decision-relevant information.
- Batch independent read-only searches and queries. Keep dependent operations, approval points, and shared or potentially conflicting writes sequential. Do not trade away error diagnosis or operational safety to reduce call count.
- Define the question and scope before reading. Prefer targeted search and relevant excerpts; read a complete plan or small file when full context is needed. Avoid broad directory dumps and oversized outputs that do not support the next decision.
- Do not reread unchanged content that remains available in context. Recheck only the part that may have changed; reread when context is missing, the file changed, or the evidence is insufficient.
- Request only enough output to support the next decision. Retain essential diagnostics for failures and concise result/count information for successful checks; avoid returning unrelated search results, entire logs, or whole files by default.
- After an initial self-contained brief, make same-thread follow-ups incremental. Use completion notifications or reasonable waits for long-running work instead of frequent status polling, while following higher-priority progress-update requirements.
- Once authorized changes, diff review, and required acceptance checks are complete and no issue remains unresolved, deliver the result. Do not add exploration, review, or reruns without a concrete purpose.
- Optimize total task cost, including reading, calls, output, waiting, and rework. Do not impose hard call or token limits, and do not save tokens by weakening acceptance, hiding failures, or skipping required verification.

## Keeping Agent Guidance Current

- When the primary agent updates this `AGENTS.md`, it must notify affected agents already working and mention the update in subsequent delegations.
- A newly started agent must read the latest applicable `AGENTS.md`. An existing agent that receives an update notice must reread it once and follow the updated guidance. Do not assume that editing the file automatically refreshes an existing agent's instructions.
- If the file has not changed, do not reread it for every follow-up. Follow the applicable higher-priority instructions if the file conflicts with them.

## Delivery Format

- Keep intermediate reports concise: completed plan step(s), key result, next step, or the specific blocker.
- Final implementation reports must state:
  1. Status (`complete pending review`, `partially complete`, or `blocked`) and the plan steps covered.
  2. Changed files and symbols, with a short summary.
  3. Applicable contracts, invariants, and cross-module interactions; include only relevant items for non-core work.
  4. Actual acceptance and Basic/Complete verification commands, results, test identifiers or counts, and the code state tested.
  5. Incomplete or unrun work, blockers, residual risks, and the smallest decision needed from the primary agent.
- State explicitly when there are no incomplete items, blockers, or known residual risks. Reports must distinguish checks that passed, failed, were not run, or were blocked.
