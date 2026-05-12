const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');

app.use(cors()); // ← deve ser o primeiro middleware
app.use(express.static(path.join(__dirname, 'frontend')));
app.use(express.json());

const userRoutes = require('./routes/users');
const corredoresRoutes = require('./routes/corredores');
const voltasRoutes = require('./routes/voltas');
const geradorRoutes = require('./routes/gerador');

app.use('/usuarios', userRoutes);
app.use('/corredores', corredoresRoutes);
app.use('/voltas', voltasRoutes);
app.use('/gerador', geradorRoutes);

module.exports = app;