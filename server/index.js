// main starting point of the application
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const app = express();
const mongoose = require('mongoose');
const router = require('./router.js');

const cors = require('cors');

// DB setup
mongoose.connect('mongodb://localhost:auth/auth', { useNewUrlParser: true });

// app setup
app.use(morgan('combined'));
app.use(cors());
app.use(bodyParser.json({ type: '*/*' }));
router(app);

// server setup
const port = process.env.PORT || 3090;
const server = http.createServer(app);
server.listen(port);
console.log('Server listening on port: ', port);
