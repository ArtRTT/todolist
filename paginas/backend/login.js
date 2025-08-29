// Pacotes necessários: os mesmos do signup (pg, bcryptjs)
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Configuração da conexão com o banco de dados Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed', headers };
  }

  try {
    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ message: 'Email e senha são obrigatórios.' }), headers };
    }

    const client = await pool.connect();
    try {
      // 1. Encontrar o usuário pelo e-mail
      const userResult = await client.query('SELECT * FROM users WHERE email = $1', [email]);
      
      // Se o usuário não for encontrado, retorna um erro genérico por segurança
      if (userResult.rowCount === 0) {
        return { statusCode: 401, body: JSON.stringify({ message: 'Credenciais inválidas.' }), headers };
      }
      
      const user = userResult.rows[0];

      // 2. Comparar a senha enviada com a senha criptografada no banco
      const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
      
      // Se as senhas não baterem, retorna o mesmo erro genérico
      if (!isPasswordCorrect) {
        return { statusCode: 401, body: JSON.stringify({ message: 'Credenciais inválidas.' }), headers };
      }

      // 3. Se tudo estiver correto, o login é bem-sucedido
      // (Em um app real, aqui você geraria um token JWT para manter o usuário logado)
      return {
        statusCode: 200,
        body: JSON.stringify({ 
          message: 'Login bem-sucedido!',
          user: { id: user.id, email: user.email }
          // token: "seu_token_jwt_aqui" 
        }),
        headers
      };

    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Erro no login:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Ocorreu um erro no servidor.' }),
      headers
    };
  }
};
