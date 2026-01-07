const jwt = require('jsonwebtoken');

/**
 * Middleware to authenticate JWT token from cookies
 * Redirects to login page if not authenticated
 */
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        console.log('No token found, redirecting to login');
        return res.redirect('/login.html');
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            res.clearCookie('token');
            return res.redirect('/login.html');
        }
        
        console.log('User authenticated:', user.username);
        req.user = user;
        next();
    });
};

/**
 * Middleware to authenticate API requests
 * Returns JSON error for API routes
 */
const authenticateApiToken = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'Authentication required. Please login.' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) {
            res.clearCookie('token');
            return res.status(403).json({ 
                success: false, 
                error: 'Invalid or expired token. Please login again.' 
            });
        }
        
        req.user = user;
        next();
    });
};

/**
 * Middleware to check if user is already logged in
 * Redirects to dashboard if already authenticated
 */
const redirectIfAuthenticated = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        return next();
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) {
            res.clearCookie('token');
            return next();
        }
        
        // User is already authenticated, redirect to dashboard
        return res.redirect('/dashboard');
    });
};

/**
 * Middleware to validate registration data
 */
const validateRegistrationData = (req, res, next) => {
    const { username, email, password } = req.body;
    const errors = [];

    // Validate username
    if (!username || username.trim().length < 3) {
        errors.push('Username must be at least 3 characters long');
    }
    
    if (username && username.length > 20) {
        errors.push('Username cannot exceed 20 characters');
    }
    
    if (username && !/^[a-zA-Z0-9_]+$/.test(username)) {
        errors.push('Username can only contain letters, numbers, and underscores');
    }

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        errors.push('Please enter a valid email address');
    }

    // Validate password
    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (password && !/(?=.*[a-z])(?=.*[A-Z])/.test(password)) {
        errors.push('Password must contain both uppercase and lowercase letters');
    }
    
    if (password && !/(?=.*\d)/.test(password)) {
        errors.push('Password must contain at least one number');
    }

    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            errors: errors 
        });
    }

    next();
};

/**
 * Middleware to validate login data
 */
const validateLoginData = (req, res, next) => {
    const { email, password } = req.body;
    const errors = [];

    if (!email || !email.trim()) {
        errors.push('Email is required');
    }

    if (!password || !password.trim()) {
        errors.push('Password is required');
    }

    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            errors: errors 
        });
    }

    next();
};

/**
 * Middleware to validate habit data
 */
const validateHabitData = (req, res, next) => {
    const { name } = req.body;
    const errors = [];

    if (!name || !name.trim()) {
        errors.push('Habit name is required');
    }
    
    if (name && name.length > 50) {
        errors.push('Habit name cannot exceed 50 characters');
    }

    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            errors: errors 
        });
    }

    next();
};

/**
 * Middleware to add user info to response locals
 * Useful for templates
 */
const addUserToLocals = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        res.locals.user = null;
        return next();
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
        if (err) {
            res.locals.user = null;
            res.clearCookie('token');
        } else {
            res.locals.user = user;
        }
        next();
    });
};

/**
 * Simple rate limiting middleware
 * Note: For production, use a proper rate limiter like express-rate-limit
 */
const rateLimit = (windowMs = 15 * 60 * 1000, maxRequests = 100) => {
    const requests = new Map();

    return (req, res, next) => {
        const ip = req.ip;
        const now = Date.now();
        
        if (!requests.has(ip)) {
            requests.set(ip, {
                count: 1,
                startTime: now
            });
        } else {
            const userRequests = requests.get(ip);
            
            if (now - userRequests.startTime > windowMs) {
                // Reset window
                userRequests.count = 1;
                userRequests.startTime = now;
            } else if (userRequests.count >= maxRequests) {
                return res.status(429).json({
                    success: false,
                    error: 'Too many requests. Please try again later.'
                });
            } else {
                userRequests.count++;
            }
        }
        
        // Clean up old entries (optional, for memory management)
        if (requests.size > 10000) {
            for (const [key, value] of requests.entries()) {
                if (now - value.startTime > windowMs) {
                    requests.delete(key);
                }
            }
        }
        
        next();
    };
};

/**
 * CSRF protection middleware (simplified version)
 * For production, use a proper CSRF library
 */
const csrfProtection = (req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        // Check for custom header or token
        // This is a simplified version
        const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
        
        if (!csrfToken) {
            return res.status(403).json({
                success: false,
                error: 'CSRF token missing'
            });
        }
        
        // In production, validate the token against session
    }
    
    next();
};

/**
 * Request logging middleware
 */
const requestLogger = (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`);
    });
    
    next();
};

/**
 * Error handling middleware
 */
const errorHandler = (err, req, res, next) => {
    console.error('Error:', err.stack);
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: 'Validation error',
            details: err.errors
        });
    }
    
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            error: 'Invalid token'
        });
    }
    
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
};

module.exports = {
    authenticateToken,
    authenticateApiToken,
    redirectIfAuthenticated,
    validateRegistrationData,
    validateLoginData,
    validateHabitData,
    addUserToLocals,
    rateLimit,
    csrfProtection,
    requestLogger,
    errorHandler
};