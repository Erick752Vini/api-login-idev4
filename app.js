const express = require('express');
const app = express();

app.use(express.json());

const userRoutes = require('./routes/corredores');
app.use('/corredores', userRoutes);


module.exports = app;