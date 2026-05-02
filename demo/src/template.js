// Mirrors CVE-2017-0931: sanitize-html — XSS via insufficient sanitisation
// Weakness description: "Cross-site scripting via unsanitized HTML output"
// Vulnerable: user-supplied bio is passed through an old sanitize-html version
//             that allows certain dangerous attributes/tags through
const sanitizeHtml = require('sanitize-html');

// VULNERABLE: old sanitize-html@1.4.2 does not strip all XSS vectors,
// e.g. <img src=x onerror="alert(1)"> passes through in some configs
function renderProfile(username, bio) {
  const sanitized = sanitizeHtml(bio || '');
  return `
    <html>
      <body>
        <h1>Profile: ${username}</h1>
        <div class="bio">${sanitized}</div>
      </body>
    </html>
  `;
}

// VULNERABLE: username itself is also not escaped
function renderComment(author, comment) {
  return `<div><strong>${author}</strong>: ${comment}</div>`;
}

module.exports = { renderProfile, renderComment };
