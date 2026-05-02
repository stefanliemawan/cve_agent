// Mirrors CVE-2017-16082: pg — incomplete string escaping / SQL injection
// Weakness description: "Incomplete string escaping or encoding"
// Vulnerable: user input is interpolated directly into the query string
const { Client } = require('pg');

const client = new Client({ connectionString: process.env.DATABASE_URL });
client.connect();

// VULNERABLE: template literal passes unsanitized `id` into SQL
async function getUserById(id) {
  const result = await client.query(`SELECT * FROM users WHERE id = ${id}`);
  return result.rows[0];
}

// VULNERABLE: string concatenation lets attacker inject SQL clauses
async function searchUsers(name) {
  const result = await client.query("SELECT * FROM users WHERE name LIKE '%" + name + "%'");
  return result.rows;
}

// SAFE reference: what the fix looks like (parameterised query)
// async function getUserByIdSafe(id) {
//   const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
//   return result.rows[0];
// }

module.exports = { getUserById, searchUsers };
