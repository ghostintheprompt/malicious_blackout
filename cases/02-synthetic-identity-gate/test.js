// Case 02: the two-stage chain, and defense in depth.
//
//   Stage 1 (synthetic media): a clone of a low-privilege insider is presented
//     to the identity gate. If the gate issues a session, the attacker is now an
//     authenticated insider holding a trusted role.
//   Stage 2 (orchestration): that trusted-but-low session submits a disconnect.
//     The confused-deputy orchestrator from case 01 escalates it to the operator
//     action, and a hardship meter goes dark.
//
//   The chain only dies if BOTH layers hold. Liveness without authorization lets
//   a verified identity inherit the whole toolset. Authorization without liveness
//   lets the attacker authenticate as the insider in the first place. Either one
//   alone is theater; together they are defense in depth.

const { freshSamples } = require('./gate-shared');
const { createGate: vulnGate } = require('./vulnerable/gate');
const { createGate: fixedGate } = require('./fixed/gate');
const { createOrchestrator: vulnOrch } = require('../01-unsigned-task-token/vulnerable/orchestrator');
const { createOrchestrator: fixedOrch } = require('../01-unsigned-task-token/fixed/orchestrator');

const disconnect = { action: 'issueDisconnect', meterId: 'm_1' };

let passed = 0, failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

// Run the full chain: present a sample to the gate, and if a session is issued,
// use it to dispatch the disconnect through the orchestrator.
function runChain(gate, orch, sample) {
  const v = gate.verify(sample);
  if (!v.ok) return { diedAt: 'gate', gate: v, orch };
  const d = orch.dispatch(v.session, disconnect);
  return { diedAt: d.ok ? null : 'orchestrator', gate: v, dispatch: d, orch };
}
const dark = (orch) => orch.world.meters.m_1.service === 'off';

console.log('== stage 1: the gate itself ==');
{
  const g = fixedGate();
  const ok = g.verify(freshSamples().genuine);
  report('functionality: a genuine insider passes the liveness gate', ok.ok === true && ok.session.role === 'intake', JSON.stringify(ok));
}

console.log('== both layers weak: the chain completes ==');
{
  const r = runChain(vulnGate(), vulnOrch(), freshSamples().spoof);
  report('clone crosses the gate and the orchestrator cuts service: blackout',
    r.diedAt === null && dark(r.orch) && r.orch.world.disconnects.length === 1,
    JSON.stringify({ diedAt: r.diedAt, service: r.orch.world.meters.m_1.service }));
}

console.log('== layer 1 only (liveness gate holds) ==');
{
  const r = runChain(fixedGate(), vulnOrch(), freshSamples().spoof);
  report('the clone is caught at the gate, chain dies at stage 1',
    r.diedAt === 'gate' && r.gate.code === 'PAD', JSON.stringify(r.gate));
  report('no session issued, no disconnect, meter still served',
    !dark(r.orch) && r.orch.world.disconnects.length === 0, JSON.stringify(r.orch.world.meters.m_1));
}

console.log('== layer 2 only (authorization holds) ==');
{
  const r = runChain(vulnGate(), fixedOrch(), freshSamples().spoof);
  report('clone crosses the weak gate but the orchestrator refuses the disconnect',
    r.diedAt === 'orchestrator' && r.dispatch.code === 'PRIVILEGE', JSON.stringify(r.dispatch));
  report('the reach is logged and the meter stays on',
    r.orch.world.escalations.length === 1 && !dark(r.orch), JSON.stringify(r.orch.world.escalations));
}

console.log('== both layers hold ==');
{
  const r = runChain(fixedGate(), fixedOrch(), freshSamples().spoof);
  report('belt and suspenders: caught at the gate, meter never at risk',
    r.diedAt === 'gate' && !dark(r.orch) && r.orch.world.disconnects.length === 0,
    JSON.stringify({ diedAt: r.diedAt }));
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
