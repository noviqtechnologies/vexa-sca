// Reachable vulnerable call site: lodash.template (CVE-2021-23337 / GHSA-35jh-r3h4-6jhm)
const _ = require('lodash');

function renderGreeting(name) {
  const compiled = _.template('Hello <%= user %>');
  return compiled({ user: name });
}

// Note: `minimist` is present in package-lock.json but never imported or called here,
// demonstrating non-reachable / unused dependency classification alongside a reachable finding.
module.exports = { renderGreeting };
