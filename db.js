const mysql2 = require('mysql2');
const dotenv = require('dotenv');
dotenv.config();

const connection = mysql2.createConnection({
    host:process.env.DB_HOST,
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DB_NAME,
    port:process.env.DB_PORT
});

connection.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return;
    } else {
        console.log('Conexão ao banco de dados estabelecida com sucesso!');
    }
});

module.exports = connection;