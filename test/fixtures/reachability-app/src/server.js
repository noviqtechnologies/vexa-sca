// Sample app code
const _ = require('lodash');

function renderUserWelcome(user) {
  // Directly invokes the vulnerable _.template method (CVE-2021-23337)
  const compiled = _.template('Hello <%= name %>!');
  return compiled({ name: user });
}

module.exports = { renderUserWelcome };
