// Mirrors CVE-2017-1000219: deasync / unsafe shell execution
// Weakness description: "Unsafe shell command constructed from library input"
// Vulnerable: user-controlled `host` reaches exec() without validation
const { exec } = require('child_process');

// VULNERABLE: `host` could be "google.com; rm -rf /" — classic shell injection
function runDiagnostic(host) {
  let output = '';
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    output = stdout;
  });
  return output;
}

// VULNERABLE: same pattern using template literal
function checkService(serviceName) {
  exec(`systemctl status ${serviceName}`, (err, stdout, stderr) => {
    console.log(stdout);
  });
}

// SAFE reference:
// const { execFile } = require('child_process');
// function runDiagnosticSafe(host) {
//   execFile('ping', ['-c', '1', host], (err, stdout) => console.log(stdout));
// }

module.exports = { runDiagnostic, checkService };
