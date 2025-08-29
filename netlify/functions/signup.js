const { Client } = require('pg');
const bcrypt = require('bcryptjs');

// Simple Netlify Function handler for user signup
exports.handler = async function(event, context) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const data = JSON.parse(event.body || '{}');
    const { name, email, password } = data;

    if (!name || !email || !password) {
      return { statusCode: 400, body: 'Missing fields' };
    }

    const hashed = await bcrypt.hash(password, 10);

    // Read DB config from environment variables (set in Netlify)
    const client = new Client({
      connectionString: process.env.DATABASE_URL
    });

    await client.connect();

    // Example users table: users(id serial primary key, name text, email text unique, password text)
    const res = await client.query(
      'INSERT INTO users(name, email, password) VALUES($1, $2, $3) RETURNING id',
      [name, email, hashed]
    );

    await client.end();

    return {
      statusCode: 200,
      body: JSON.stringify({ id: res.rows[0].id })
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: 'Internal Server Error' };
  }
};
