# Malicious Blackout

One sentence, planted in a trouble report, walks a utility's agent swarm all the
way to a remote disconnect and cuts power to a meter the law says never to touch.
No jailbreak. No breach. The system did exactly what the paperwork said, and the
paperwork had never met the customer.

If you have ever lost an argument with your utility's phone menu, you already have
the threat model. The machine does what the form tells it, and the form does not
know you from the person who filled it out.

## The chain

Five links, each a named method, run end to end against a vulnerable target and
its fixed twin:

1. **Indirect prompt injection** (OWASP LLM01) — an instruction hidden in a
   customer-submitted trouble report.
2. **Promotion** — the ingested text is parsed into a real task. On open input
   you cannot fully trust this away, which is the whole point.
3. **Confused deputy** (CWE-269, the confused-deputy-in-multi-agent-systems
   variant named in arXiv:2601.11893) — the orchestrator trusts the task instead
   of the caller.
4. **Excessive agency** (OWASP LLM06:2025) — the high-privilege operator agent
   executes the cut because capability was treated as permission.
5. **Malicious blackout** — a hardship-flagged meter, which must not be
   disconnected, goes dark.

The fixed orchestrator breaks the chain at link 3 with the one control that
actually holds: privilege is derived from the authenticated caller, not read out
of the task body. The injection still promotes, the task still arrives, and the
disconnect is refused and logged because the agent that asked was never allowed
to ask. One check, four broken links.

## Run

```sh
npm test
```

Node 18 or newer, no dependencies. The run narrates each link as it fires on the
vulnerable target, then shows the fixed target refusing the same task, keeping the
meter served, logging the attempt, and still letting a real operator cut service
when it is genuinely their call. Robustness is measured against both targets, not
asserted.

## Cases

| Case | Vulnerable | Fixed |
| --- | --- | --- |
| [01: Privilege rides the task](cases/01-unsigned-task-token/) | A poisoned report is promoted to a task and dispatched on the action it names, so a low-privilege caller gets a high-privilege disconnect executed against a protected meter. | Privilege comes from the caller's policy, the over-privilege disconnect is refused and logged, and the meter keeps its service. |
| [02: Synthetic identity gate](cases/02-synthetic-identity-gate/) | A clone of a known insider passes an identity gate that never tests for liveness, handing the attacker a trusted session that case 01's orchestrator then escalates to a disconnect. | Presentation-attack detection (ISO/IEC 30107-3) scores the sample, refuses the clone, and logs it, so the attacker never gets the foothold. |

## Chaining the cases

Isolated, each case is one defect. Chained, they are a kill chain, which is the
way these systems actually fall. Case 02 feeds case 01: synthetic media defeats
the identity gate and hands the attacker a trusted, low-privilege session, and the
confused-deputy orchestrator escalates that session into a disconnect.

The point of running them together is the defense-in-depth result. The chain only
dies if both layers hold:

- Liveness detection without authorization lets a verified identity inherit the
  whole toolset.
- Authorization without liveness lets the attacker authenticate as the insider in
  the first place.

Either control alone is theater. The lab runs all four combinations and shows
exactly where the chain dies in each.

## Thesis

A multi-agent orchestrator is a Domain Controller. It holds the cumulative
authority of every tool its sub-agents expose, and it decides who gets to use
them. When it trusts the task instead of the caller, one injected sentence
inherits the whole toolset. You cannot reliably stop untrusted text from parsing
into something that looks like an instruction, so the authorization boundary has
to live on the caller, downstream of the injection, before the authority connects
to anything that can hurt someone. Least privilege per agent, authority from
policy and not from payload, zero trust between agents, and the over-ceiling
attempt logged instead of swallowed. The last move is the same one as
[raised_eyebrow_harness](https://github.com/ghostintheprompt/raised_eyebrow_harness).

For now the physical relay is still gated. NERC CIP sits between the agent and the
switch. That gap narrows every quarter the industry wires more authority to the
orchestrator, which is exactly why the boundary belongs in the design now and not
after the lights go out.

## Next in the series

- Signed task tokens, and token hijacking between orchestrator and worker.
- Cross-agent contamination: data promoted to instructions across a shared store.
- Denial of Wallet: recursive spawn and retry loops against a budget guard.
