const express = require('express');
const routes = express.Router();
const db = require('../db');
const bcrypt = require('bcrypt');

routes.get('/', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar usuários' });
        }
        res.json(results);
    });
});

routes.post('/z', (req, res) => {
    const { nome, email } = req.body; 

    db.query('INSERT INTO users (nome, email) VALUES (?, ?)', [nome, email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao criar usuário' });
        }
        res.status(201).json({ message: 'Usuário criado com sucesso', id: result.insertId });
    });
});

routes.put('edit/:id', (req, res) => {
    const { id } = req.params; 
    const { nome, email } = req.body; 

    db.query('UPDATE users SET nome = ?, email = ? WHERE id = ?', [nome, email, id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao atualizar usuário' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }
        
        res.json({ message: 'Usuário atualizado com sucesso' });
    });
});

routes.delete('delete/:id', (req, res) => {
    const { id } = req.params; 

    db.query('DELETE FROM users WHERE id = ?', [id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao deletar usuário' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }
        
        res.json({ message: 'Usuário deletado com sucesso' });
    });
});

module.exports = routes;
