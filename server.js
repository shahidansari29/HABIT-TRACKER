const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.static('views'));

// Database setup
let db;

async function initializeDatabase() {
    try {
        db = await open({
            filename: './habittracker.db',
            driver: sqlite3.Database
        });
        
        console.log('✅ SQLite Database Connected');
        
        // Create tables if they don't exist
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS habits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                color TEXT DEFAULT '#00ff00',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS habit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                habit_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                date DATE NOT NULL,
                completed BOOLEAN DEFAULT 0,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(habit_id, user_id, date),
                FOREIGN KEY (habit_id) REFERENCES habits(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_habits_user_id ON habits(user_id);
            CREATE INDEX IF NOT EXISTS idx_habit_logs_user_id ON habit_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_habit_logs_date ON habit_logs(date);
        `);
        
        console.log('✅ Database tables created/verified');
        
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
}

// Initialize database
initializeDatabase();

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login.html');

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) return res.redirect('/login.html');
        req.user = user;
        next();
    });
};

// API Authentication Middleware
const authenticateApiToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Routes

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/index.html');
});

app.get('/login.html', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.get('/register.html', (req, res) => {
    res.sendFile(__dirname + '/views/register.html');
});

app.get('/dashboard', authenticateToken, (req, res) => {
    res.sendFile(__dirname + '/views/dashboard.html');
});

// API Routes

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user exists
        const existingUser = await db.get(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const result = await db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        // Create token
        const token = jwt.sign(
            { userId: result.lastID, username: username },
            process.env.JWT_SECRET || 'your_secret_key',
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ 
            success: true, 
            message: 'Registration successful',
            user: {
                id: result.lastID,
                username,
                email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await db.get(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Create token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET || 'your_secret_key',
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ 
            success: true, 
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Logged out' });
});

// Get user data
app.get('/api/user', authenticateApiToken, async (req, res) => {
    try {
        const user = await db.get(
            'SELECT id, username, email, created_at FROM users WHERE id = ?',
            [req.user.userId]
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Habit CRUD operations
app.get('/api/habits', authenticateApiToken, async (req, res) => {
    try {
        const habits = await db.all(
            'SELECT * FROM habits WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.userId]
        );
        res.json(habits);
    } catch (error) {
        console.error('Get habits error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/habits', authenticateApiToken, async (req, res) => {
    try {
        const { name, description, color } = req.body;
        const result = await db.run(
            'INSERT INTO habits (user_id, name, description, color) VALUES (?, ?, ?, ?)',
            [req.user.userId, name, description || '', color || '#00ff00']
        );
        
        const habit = await db.get(
            'SELECT * FROM habits WHERE id = ?',
            [result.lastID]
        );
        
        res.json(habit);
    } catch (error) {
        console.error('Create habit error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/habits/:id', authenticateApiToken, async (req, res) => {
    try {
        await db.run(
            'DELETE FROM habits WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.userId]
        );
        
        res.json({ success: true, message: 'Habit deleted' });
    } catch (error) {
        console.error('Delete habit error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Habit Log operations
app.get('/api/habit-logs', authenticateApiToken, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        const logs = await db.all(`
            SELECT hl.*, h.name, h.color 
            FROM habit_logs hl 
            JOIN habits h ON hl.habit_id = h.id 
            WHERE hl.user_id = ? 
            AND date(hl.date) BETWEEN date(?) AND date(?)
            ORDER BY hl.date DESC
        `, [req.user.userId, startDate || '2024-01-01', endDate || '2024-12-31']);
        
        res.json(logs);
    } catch (error) {
        console.error('Error getting logs:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/habit-logs', authenticateApiToken, async (req, res) => {
    try {
        const { habitId, date, completed, notes } = req.body;
        
        // Check if habit belongs to user
        const habit = await db.get(
            'SELECT * FROM habits WHERE id = ? AND user_id = ?',
            [habitId, req.user.userId]
        );
        
        if (!habit) {
            return res.status(404).json({ error: 'Habit not found' });
        }
        
        try {
            // Try to insert or update
            await db.run(`
                INSERT INTO habit_logs (habit_id, user_id, date, completed, notes) 
                VALUES (?, ?, date(?), ?, ?)
                ON CONFLICT(habit_id, user_id, date) 
                DO UPDATE SET completed = excluded.completed, notes = excluded.notes
            `, [habitId, req.user.userId, date, completed ? 1 : 0, notes || '']);
            
            // Get the updated log
            const log = await db.get(`
                SELECT hl.*, h.name, h.color 
                FROM habit_logs hl 
                JOIN habits h ON hl.habit_id = h.id 
                WHERE hl.habit_id = ? AND hl.user_id = ? AND hl.date = date(?)
            `, [habitId, req.user.userId, date]);
            
            res.json(log);
            
        } catch (conflictError) {
            // If conflict handling fails, do update manually
            await db.run(`
                UPDATE habit_logs 
                SET completed = ?, notes = ? 
                WHERE habit_id = ? AND user_id = ? AND date = date(?)
            `, [completed ? 1 : 0, notes || '', habitId, req.user.userId, date]);
            
            const log = await db.get(`
                SELECT hl.*, h.name, h.color 
                FROM habit_logs hl 
                JOIN habits h ON hl.habit_id = h.id 
                WHERE hl.habit_id = ? AND hl.user_id = ? AND hl.date = date(?)
            `, [habitId, req.user.userId, date]);
            
            res.json(log);
        }
        
    } catch (error) {
        console.error('Error saving log:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get logs for a specific date
app.get('/api/habit-logs/:date', authenticateApiToken, async (req, res) => {
    try {
        const logs = await db.all(`
            SELECT hl.*, h.name, h.color, h.description 
            FROM habit_logs hl 
            JOIN habits h ON hl.habit_id = h.id 
            WHERE hl.user_id = ? AND hl.date = date(?)
        `, [req.user.userId, req.params.date]);
        
        res.json(logs);
    } catch (error) {
        console.error('Error getting daily logs:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Statistics
app.get('/api/stats', authenticateApiToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Get counts
        const habitCount = await db.get(
            'SELECT COUNT(*) as count FROM habits WHERE user_id = ?',
            [userId]
        );
        
        const logCount = await db.get(
            'SELECT COUNT(*) as count FROM habit_logs WHERE user_id = ?',
            [userId]
        );
        
        const completedCount = await db.get(
            'SELECT COUNT(*) as count FROM habit_logs WHERE user_id = ? AND completed = 1',
            [userId]
        );
        
        // Calculate success rate
        const successRate = logCount.count > 0 
            ? Math.round((completedCount.count / logCount.count) * 100) 
            : 0;
        
        // Get current streak
        const today = new Date().toISOString().split('T')[0];
        const streakResult = await db.get(`
            WITH RECURSIVE dates AS (
                SELECT date(?) as check_date
                UNION ALL
                SELECT date(check_date, '-1 day')
                FROM dates
                WHERE check_date > date('now', '-30 days')
            )
            SELECT COUNT(*) as streak
            FROM dates d
            WHERE EXISTS (
                SELECT 1 FROM habit_logs hl
                WHERE hl.user_id = ? 
                AND hl.date = d.check_date
                AND hl.completed = 1
            )
            AND NOT EXISTS (
                SELECT 1 FROM habit_logs hl
                WHERE hl.user_id = ? 
                AND hl.date = d.check_date
                AND hl.completed = 0
            )
            ORDER BY d.check_date DESC
            LIMIT 1
        `, [today, userId, userId]);
        
        res.json({
            totalHabits: habitCount.count,
            totalLogs: logCount.count,
            completedLogs: completedCount.count,
            successRate: successRate,
            currentStreak: streakResult ? streakResult.streak : 0
        });
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get calendar data for a month
app.get('/api/calendar/:year/:month', authenticateApiToken, async (req, res) => {
    try {
        const { year, month } = req.params;
        const userId = req.user.userId;
        
        const logs = await db.all(`
            SELECT 
                date(hl.date) as date,
                hl.completed,
                h.name,
                h.color
            FROM habit_logs hl
            JOIN habits h ON hl.habit_id = h.id
            WHERE hl.user_id = ?
            AND strftime('%Y', hl.date) = ?
            AND strftime('%m', hl.date) = ?
            ORDER BY hl.date
        `, [userId, year, month.padStart(2, '0')]);
        
        res.json(logs);
    } catch (error) {
        console.error('Error getting calendar data:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create test data endpoint (for development)
app.post('/api/test-data', authenticateApiToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Create some test habits
        const habits = [
            ['Morning Exercise', 'Do 30 mins of exercise', '#00ff00'],
            ['Meditation', 'Meditate for 10 minutes', '#ff00ff'],
            ['Reading', 'Read 20 pages', '#ffff00'],
            ['Coding', 'Code for 1 hour', '#00ffff'],
            ['Water', 'Drink 8 glasses of water', '#0000ff']
        ];
        
        for (const [name, description, color] of habits) {
            await db.run(
                'INSERT INTO habits (user_id, name, description, color) VALUES (?, ?, ?, ?)',
                [userId, name, description, color]
            );
        }
        
        res.json({ success: true, message: 'Test data created' });
    } catch (error) {
        console.error('Error creating test data:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Health check
app.get('/health', async (req, res) => {
    try {
        const dbStatus = db ? 'connected' : 'disconnected';
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            database: dbStatus
        });
    } catch (error) {
        res.status(500).json({ status: 'ERROR', error: error.message });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).send('404 - Not Found');
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 Database: habittracker.db (SQLite)`);
});