const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

// Test route
app.get('/api/test', (req, res) => {
    res.status(200).send('Backend is working!');
});

// Export for Vercel
module.exports = app;
