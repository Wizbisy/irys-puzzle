const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({ origin: 'https://irys-puzzle.vercel.app' }));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

const userSchema = new mongoose.Schema({
    discordId: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    points: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);

app.get('/auth/discord', (req, res) => {
    const redirectUri = encodeURIComponent(process.env.DISCORD_REDIRECT_URI);
    const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=identify`;
    res.redirect(authUrl);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        console.error('No code provided in callback');
        return res.status(400).send('No code provided');
    }

    try {
        console.log('Attempting token exchange with code:', code);
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code,
            redirect_uri: process.env.DISCORD_REDIRECT_URI
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token } = tokenResponse.data;
        console.log('Token exchange successful, fetching user info');

        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const { id: discordId, username } = userResponse.data;
        console.log('User info fetched:', { discordId, username });

        let user = await User.findOne({ discordId });
        if (!user) {
            user = new User({ discordId, username });
            await user.save();
            console.log('New user created:', discordId);
        }

        const token = jwt.sign({ discordId, username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const redirectUrl = `https://irys-puzzle.vercel.app?discordId=${discordId}&username=${encodeURIComponent(username)}&token=${token}`;
        console.log('Redirecting to:', redirectUrl);
        res.redirect(redirectUrl);
    } catch (error) {
        console.error('OAuth error:', {
            message: error.response ? error.response.data : error.message,
            status: error.response ? error.response.status : 'unknown',
            code: req.query.code
        });
        res.status(500).send('Authentication failed');
    }
});

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('No token provided');

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).send('Invalid token');
        }
        req.user = user;
        next();
    });
};

app.post('/update-points', authenticateJWT, async (req, res) => {
    const { discordId, points } = req.body;
    if (discordId !== req.user.discordId) return res.status(403).send('Unauthorized');

    try {
        const user = await User.findOne({ discordId });
        if (!user) return res.status(404).send('User not found');

        user.points += points;
        await user.save();
        res.json({ success: true, points: user.points });
    } catch (error) {
        console.error('Update points error:', error);
        res.status(500).send('Server error');
    }
});

app.get('/leaderboard', async (req, res) => {
    try {
        const leaderboard = await User.find().sort({ points: -1 }).limit(10);
        res.json(leaderboard);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).send('Server error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
