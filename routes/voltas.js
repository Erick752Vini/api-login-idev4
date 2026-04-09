const express = require('express');
const routes = express.Router();
const db = require('../db');

routes.get('/', (req, res) => {
    db.query('SELECT * FROM voltas', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar voltas' });
        }
        res.json(results);
    });
});

routes.get('/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM voltas WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar volta' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Volta não encontrada' });
        }
        res.status(200).json(results[0]);
    });
});

routes.post('/create', (req, res) => {
    const { tempo, data, corredores_id } = req.body;

    if (!corredores_id) {
        return res.status(400).json({ error: 'O campo corredores_id é obrigatório' });
    }

    db.query(
        'INSERT INTO voltas (tempo, data, corredores_id) VALUES (?, ?, ?)',
        [tempo, data, corredores_id],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao criar volta' });
            }
            res.status(201).json({ id: result.insertId, tempo, data, corredores_id });
        }
    );
});

routes.put('/:id', (req, res) => {
    const { id } = req.params;
    const { tempo, data, corredores_id } = req.body;

    if (!corredores_id) {
        return res.status(400).json({ error: 'O campo corredores_id é obrigatório' });
    }

    db.query(
        'UPDATE voltas SET tempo = ?, data = ?, corredores_id = ? WHERE id = ?',
        [tempo, data, corredores_id, id],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao atualizar volta' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Volta não encontrada' });
            }
            res.status(200).json({ id, tempo, data, corredores_id });
        }
    );
});

routes.delete('/delete/:id', (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM voltas WHERE id = ?', [id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao deletar volta' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Volta não encontrada' });
        }
        res.status(200).json({ message: 'Volta deletada com sucesso' });
    });
});

module.exports = routes;
