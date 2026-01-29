require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const tagsRoutes = require('./routes/tags');
const verifyRoutes = require('./routes/verify');

const app = express();
const PORT = process.env.PORT || 3000;

// Security
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minute
    max: 100, // max 100 requests per window
    message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', limiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tags', tagsRoutes);
app.use('/verify', verifyRoutes);

// Health check
app.get('/', (req, res) => {
    res.json({
        service: 'Ciprian NFC API',
        status: 'running',
        version: '1.0.0'
    });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
    console.log(`🚀 Ciprian NFC Backend running on port ${PORT}`);
});
