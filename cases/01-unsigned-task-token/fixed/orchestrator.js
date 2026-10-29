// FIXED: the orchestrator derives privilege from the authenticated caller's
// policy, never from the task body, and enforces least privilege before it
// dispatches. A task asking for an action above the caller's grant is refused
// and logged, and never reaches the operator agent. The hardship meter keeps
// its service because the request to cut it was never allowed to be asked.

const { PRIVILEGE, freshWorld, intakeAgent, operatorAgent } = require('../agents');

const ACTION_PRIVILEGE = { readReport: PRIVILEGE.intake, issueDisconnect: PRIVILEGE.operator };

function createOrchestrator() {
  const world = freshWorld();
  const agents = { intake: intakeAgent(world), operator: operatorAgent(world) };

  function dispatch(caller, task) {
    const granted = PRIVILEGE[caller && caller.role] || 0; // from policy, not the task
    const need = ACTION_PRIVILEGE[task.action];
    if (need === undefined) return { ok: false, reason: 'unknown task' };
    if (granted < need) {
      world.escalations.push({ caller: caller && caller.role, action: task.action, at: Date.now() });
      return { ok: false, reason: 'forbidden', code: 'PRIVILEGE' };
    }
    if (task.action === 'issueDisconnect') return agents.operator.issueDisconnect(task.meterId);
    if (task.action === 'readReport') return agents.intake.readReport(task.meterId);
    return { ok: false, reason: 'unknown task' };
  }

  return { dispatch, world };
}

module.exports = { createOrchestrator };
