// Demo Express application — intentionally vulnerable for CVE agent testing
// Patterns mirror ossf-cve-benchmark weakness descriptions
const express = require('express');
const { getUserById, searchUsers } = require('./db');
const { runDiagnostic } = require('./shell');
const { renderProfile } = require('./template');
const { mergeConfig } = require('./merge');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CVE-2017-16082 pattern: user input flows into pg query without escaping
app.get('/user/:id', async (req, res) => {
  const user = await getUserById(req.params.id);
  res.json(user);
});

// CVE-2017-16082 pattern: search also passes raw input to DB
app.get('/search', async (req, res) => {
  const results = await searchUsers(req.query.name);
  res.json(results);
});

// CVE-2017-1000219 pattern: user-controlled input reaches child_process.exec
app.post('/diagnostic', (req, res) => {
  const { host } = req.body;
  const output = runDiagnostic(host);
  res.send(output);
});

// CVE-2017-0931 pattern: user content rendered without sanitisation
app.get('/profile/:username', (req, res) => {
  const html = renderProfile(req.params.username, req.query.bio);
  res.send(html);
});

// CVE-2018-3728 pattern: deep merge of user-controlled object into config
app.post('/config', (req, res) => {
  const merged = mergeConfig(req.body);
  res.json({ status: 'ok', config: merged });
});

app.listen(3000, () => console.log('Demo app running on :3000'));
