const express = require('express');
const routes = express.Router();
const db = require('../db');

// ─── GET todas as voltas ──────────────────────────────────────────────────────
routes.get('/', (req, res) => {
    db.query('SELECT * FROM voltas ORDER BY corrida_num ASC, data ASC', (err, results) => {
        if (err) return res.status(500).json({ error: 'Erro ao buscar voltas' });
        res.json(results);
    });
});

// ─── GET médias por corredor (todas as corridas) ──────────────────────────────
// Retorna: para cada corredor, a média de tempo em cada corrida + média geral
routes.get('/medias', (req, res) => {
    const sql = `
        SELECT
            c.id             AS corredor_id,
            c.nome           AS corredor_nome,
            c.turma          AS corredor_turma,
            v.corrida_num,
            COUNT(v.id)      AS total_voltas,
            MIN(v.tempo)     AS melhor_tempo,
            AVG(v.tempo)     AS media_tempo,
            MAX(v.tempo)     AS pior_tempo
        FROM corredores c
        LEFT JOIN voltas v ON v.corredores_id = c.id
        GROUP BY c.id, c.nome, c.turma, v.corrida_num
        ORDER BY c.id ASC, v.corrida_num ASC
    `;

    db.query(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Erro ao calcular médias' });

        // Agrupa por corredor
        const map = {};
        rows.forEach(row => {
            if (!map[row.corredor_id]) {
                map[row.corredor_id] = {
                    id: row.corredor_id,
                    nome: row.corredor_nome,
                    turma: row.corredor_turma,
                    corridas: [],
                    geral: { total_voltas: 0, soma_tempos: 0, melhor_tempo: null, media_geral: null }
                };
            }

            // Só registra se tiver corrida_num (LEFT JOIN pode trazer NULL)
            if (row.corrida_num !== null) {
                const media = parseFloat(row.media_tempo);
                const melhor = parseFloat(row.melhor_tempo);

                map[row.corredor_id].corridas.push({
                    corrida_num: row.corrida_num,
                    total_voltas: row.total_voltas,
                    melhor_tempo: melhor.toFixed(2),
                    media_tempo: media.toFixed(2),
                    pior_tempo: parseFloat(row.pior_tempo).toFixed(2)
                });

                // Acumula para média geral
                const g = map[row.corredor_id].geral;
                g.total_voltas += row.total_voltas;
                g.soma_tempos  += media * row.total_voltas;
                if (g.melhor_tempo === null || melhor < g.melhor_tempo) {
                    g.melhor_tempo = melhor;
                }
            }
        });

        // Calcula média geral de cada corredor
        const resultado = Object.values(map).map(c => {
            const g = c.geral;
            if (g.total_voltas > 0) {
                g.media_geral  = (g.soma_tempos / g.total_voltas).toFixed(2);
                g.melhor_tempo = g.melhor_tempo.toFixed(2);
            }
            delete g.soma_tempos;
            return c;
        });

        res.json(resultado);
    });
});

// ─── GET voltas de um corredor específico ─────────────────────────────────────
routes.get('/corredor/:corredorId', (req, res) => {
    const { corredorId } = req.params;
    db.query(
        'SELECT * FROM voltas WHERE corredores_id = ? ORDER BY corrida_num ASC, data ASC',
        [corredorId],
        (err, results) => {
            if (err) return res.status(500).json({ error: 'Erro ao buscar voltas do corredor' });
            res.json(results);
        }
    );
});

// ─── POST criar volta ─────────────────────────────────────────────────────────
routes.post('/create', (req, res) => {
    const { tempo, data, corredores_id, corrida_num } = req.body;

    if (!corredores_id) return res.status(400).json({ error: 'O campo corredores_id é obrigatório' });
    if (!tempo)         return res.status(400).json({ error: 'O campo tempo é obrigatório' });

    // corrida_num padrão = 1 se não informado
    const numCorrida = corrida_num || 1;
    const dataVolta  = data || new Date();

    // Valida que corrida_num está entre 1 e 8
    if (numCorrida < 1 || numCorrida > 8) {
        return res.status(400).json({ error: 'corrida_num deve ser entre 1 e 8' });
    }

    db.query(
        'INSERT INTO voltas (tempo, data, corredores_id, corrida_num) VALUES (?, ?, ?, ?)',
        [tempo, dataVolta, corredores_id, numCorrida],
        (err, result) => {
            if (err) return res.status(500).json({ error: 'Erro ao criar volta' });
            res.status(201).json({ id: result.insertId, tempo, data: dataVolta, corredores_id, corrida_num: numCorrida });
        }
    );
});

// ─── PUT atualizar volta ──────────────────────────────────────────────────────
routes.put('/:id', (req, res) => {
    const { id } = req.params;
    const { tempo, data, corredores_id, corrida_num } = req.body;

    if (!corredores_id) return res.status(400).json({ error: 'O campo corredores_id é obrigatório' });

    db.query(
        'UPDATE voltas SET tempo = ?, data = ?, corredores_id = ?, corrida_num = ? WHERE id = ?',
        [tempo, data, corredores_id, corrida_num || 1, id],
        (err, result) => {
            if (err) return res.status(500).json({ error: 'Erro ao atualizar volta' });
            if (result.affectedRows === 0) return res.status(404).json({ error: 'Volta não encontrada' });
            res.status(200).json({ id, tempo, data, corredores_id, corrida_num });
        }
    );
});

// ─── DELETE volta ─────────────────────────────────────────────────────────────
routes.delete('/:id', (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM voltas WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Erro ao deletar volta' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Volta não encontrada' });
        res.status(200).json({ message: 'Volta deletada com sucesso' });
    });
});

// ─── GET volta por ID ─────────────────────────────────────────────────────────
routes.get('/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM voltas WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: 'Erro ao buscar volta' });
        if (results.length === 0) return res.status(404).json({ error: 'Volta não encontrada' });
        res.status(200).json(results[0]);
    });
});

module.exports = routes;