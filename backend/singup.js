// Pacotes necessários: instale com "npm install pg bcryptjs"
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Configuração da conexão com o banco de dados Neon
// O Netlify vai pegar essa string das suas variáveis de ambiente
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Necessário para conexões com o Neon
  }
});

exports.handler = async (event) => {
  // Permite que a função seja chamada de qualquer origem (CORS)
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // O Netlify faz uma chamada 'OPTIONS' primeiro para verificar o CORS
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers
    };
  }

  // Apenas permite requisições do tipo POST
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed', headers };
  }

  try {
    const { email, password } = JSON.parse(event.body);

    // Validação básica
    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ message: 'Email e senha são obrigatórios.' }), headers };
    }

    // 1. Criptografar a senha antes de salvar
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 2. Conectar ao banco de dados e inserir o novo usuário
    const client = await pool.connect();
    try {
      // Verifica se o usuário já existe
      const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userExists.rowCount > 0) {
        return { statusCode: 409, body: JSON.stringify({ message: 'Este email já está em uso.' }), headers };
      }
      
      // Insere o novo usuário na tabela 'users'
      // Você precisa ter uma tabela 'users' com colunas 'email' e 'password_hash'
      const queryText = 'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email';
      const res = await client.query(queryText, [email, hashedPassword]);
      
      return {
        statusCode: 201, // 201 Created
        body: JSON.stringify({ 
          message: 'Usuário criado com sucesso!', 
          user: res.rows[0] 
        }),
        headers
      };

    } finally {
      // Libera a conexão com o banco, independentemente do resultado
      client.release();
    }

  } catch (error) {
    console.error('Erro no cadastro:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Ocorreu um erro no servidor.' }),
      headers
    };
  }
};
