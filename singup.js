// Pacotes necessários: instale com "npm install pg bcryptjs"
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
  // Cabeçalhos para permitir requisições de outras origens (CORS)
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ message: 'Método não permitido.' }), headers };
  }

  try {
    // Tenta extrair os dados do corpo da requisição
    // Se o corpo estiver vazio ou mal formatado, vai para o catch
    if (!event.body) {
        throw new Error("Corpo da requisição está vazio.");
    }
    const { email, password } = JSON.parse(event.body);

    // Validação dos campos
    if (!email || !password) {
      // A resposta de erro agora é um JSON
      return { statusCode: 400, body: JSON.stringify({ message: 'Email e senha são obrigatórios.' }), headers };
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const client = await pool.connect();
    try {
      const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userExists.rowCount > 0) {
        return { statusCode: 409, body: JSON.stringify({ message: 'Este email já está em uso.' }), headers };
      }
      
      const queryText = 'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email';
      const res = await client.query(queryText, [email, hashedPassword]);
      
      return {
        statusCode: 201,
        body: JSON.stringify({ 
          message: 'Usuário criado com sucesso!', 
          user: res.rows[0] 
        }),
        headers
      };

    } finally {
      client.release();
    }

  } catch (error) {
    // CORREÇÃO APLICADA AQUI: Garante que o objeto de erro real seja logado
    console.error('Erro no cadastro:', error); 
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Ocorreu um erro no servidor. Verifique os dados enviados.' }),
      headers
    };
  }
};
