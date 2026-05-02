// Mirrors CVE-2018-3728: hoek — prototype pollution via deep clone/merge
// Weakness description: "Prototype pollution via merge of user-controlled object"
// Vulnerable: hoek@4.2.0 merge does not block __proto__ assignment
const hoek = require('hoek');

const DEFAULT_CONFIG = {
  timeout: 5000,
  retries: 3,
  logLevel: 'info',
};

// VULNERABLE: if userConfig contains {"__proto__": {"isAdmin": true}}
// hoek.merge propagates this onto Object.prototype in hoek < 4.2.1
function mergeConfig(userConfig) {
  return hoek.merge(DEFAULT_CONFIG, userConfig);
}

// VULNERABLE: hoek.clone also affected
function cloneWithDefaults(data) {
  return hoek.clone(data);
}

// SAFE reference (after patch):
// const _ = require('lodash'); // >= 4.17.21
// function mergeConfigSafe(userConfig) {
//   return _.merge({}, DEFAULT_CONFIG, userConfig); // lodash >= 4.17.21 blocks __proto__
// }

module.exports = { mergeConfig, cloneWithDefaults };
