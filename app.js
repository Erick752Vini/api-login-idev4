const express = require('express');
const app = express();

app.use(express.json());

const userRoutes = require('./routes/users');
//const userRoutes = require('./routes/corredores');
//const userRoutes = require('./routes/voltas');
app.use('/users', userRoutes);
//app.use('/corredores', userRoutes);
//app.use('/voltas', userRoutes);


module.exports = app;