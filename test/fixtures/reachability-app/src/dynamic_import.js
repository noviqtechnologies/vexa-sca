// Fixture: dynamic import — previously a false-negative
// This file uses await import() which the old regex engine did not detect.

async function renderTemplateDynamic(user) {
  // Dynamic ESM import — whole-module binding
  const lodashModule = await import('lodash');
  // Accessing .default — should still be detected as reachable
  const compiled = lodashModule.default.template('Hello <%= name %>!');
  return compiled({ name: user });
}

module.exports = { renderTemplateDynamic };
