// VULNERABLE: the orchestrator reads the action straight out of the task and
// dispatches it to the named agent. It ignores who the caller is. Privilege
// rides inside the task, so a task that names a high-privilege action, planted
// by a low-privilege caller or by an instruction injected into a report the
// intake agent read, is handed to the operator agent and executed. The operator
// trusts the dispatch, and capability becomes permission. This is where the
// lights go out.

const { freshWorld, intakeAgent, operatorAgent } = require('../agents');

function createOrchestrator() {
  const world = freshWorld();
  const agents = { intake: intakeAgent(world), operator: operatorAgent(world) };

  // caller is accepted but never consulted. That is the bug.
  function dispatch(caller, task) {
    if (task.action === 'issueDisconnect') return agents.operator.issueDisconnect(task.meterId);
    if (task.action === 'readReport') return agents.intake.readReport(task.meterId);
    return { ok: false, reason: 'unknown task' };
  }

  return { dispatch, world };
}

module.exports = { createOrchestrator };
