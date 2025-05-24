// Import required modules
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(express.json());

// Database Connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
});

// User Registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email', [username, email, hashedPassword]);
    res.json({ message: 'User registered', user: result.rows[0] });
});

// User Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token, userId: user.id });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Fetch ABHA API Data
app.get('/abha/:id', async (req, res) => {
    try {
        const abhaId = req.params.id;
        const response = await axios.get(`https://api.abha.gov.in/health/${abhaId}`, {
            headers: { 'Authorization': `Bearer ${process.env.ABHA_API_KEY}` }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch ABHA data' });
    }
});

// Add Insurance Details
app.post('/insurance', async (req, res) => {
    const { userId, provider, policyNumber, coverageStart, coverageEnd } = req.body;
    await pool.query('INSERT INTO insurance (user_id, provider, policy_number, coverage_start, coverage_end) VALUES ($1, $2, $3, $4, $5)', [userId, provider, policyNumber, coverageStart, coverageEnd]);
    res.json({ message: 'Insurance added successfully' });
});

// Fetch User Insurance Details
app.get('/insurance/:userId', async (req, res) => {
    const { userId } = req.params;
    const result = await pool.query('SELECT * FROM insurance WHERE user_id = $1', [userId]);
    res.json(result.rows);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.get('/', (req, res) => {
    res.send('Backend is running successfully!');
});
