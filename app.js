//BACKEND
//ez egy teszt kristóftól
const dotenv = require('dotenv');
dotenv.config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const mysql = require('mysql2');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const fs = require('fs');
const path = require('path');
const { log } = require('console');
const cookieparser = require('cookie-parser');
const nodemailer = require('nodemailer');
const stripeReq = require('stripe');
const stripe = stripeReq(process.env.STRIPE_SECRET_KEY);

console.log('Stripe key loaded:', process.env.STRIPE_SECRET_KEY ? 'Yes' : 'No');

//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

const app = express();
const server = http.createServer(app);
app.use(express.urlencoded({ extended: true }));
app.use(cookieparser());
app.use('/uploads', express.static('uploads'));


const PORT = process.env.PORT;
const HOSTNAME = process.env.HOSTNAME;

app.use(cors({
    origin: "https://extraordinary-parfait-60b553.netlify.app",
    credentials: true
    // methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    // allowedHeaders: [
    //     'Access-Control-Allow_Origin',
    //     'Content-Type',
    //     'Authorization'
    // ]
}));





const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const promisePool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 2  // Smaller connection limit since it's just for password reset
}).promise();



const uploadDir = 'uploads/';
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const now = new Date().toISOString().split('T')[0];
        cb(null, `${req.user.id}-${now}-${file.originalname}`);
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|webp|avif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb(new Error('Csak képformátumok megengedettek'));
        }
    }
});


const JWT_SECRET = process.env.JWT_SECRET;
function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;

    if (!token) {
        return res.status(403).json({ error: 'Nincsen tokened he' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Van tokened, de nem jáó' });
        }

        console.log(user)

        req.user = user;
        next();
    });

    console.log(token);
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.use(express.static(path.join(__dirname, '../casinoFrontend')));

//Ratelimit
const limiter = rateLimit({
    widnowMs: 1000 * 60 * 15,
    max:100
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//Felhasznalok lekerdezese
app.get('/users',(req,res)=>{
    pool.query('SELECT userid, username, password, email, role, balance, balance_last_update, profile_pic FROM users',(err,result)=>{
        if(err){
            return res.status(500).json({error: 'Adatbazis hiba!'});
        }
        if(result.length===0){
            return res.status(404).json({ error: 'Nem talalhato!'  });
        }

        return res.status(200).json(result);
    });
});

//Profilkep lekerdezese
app.get('/api/user/profilePic', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    pool.query('SELECT profile_pic FROM users WHERE user_id = ?', [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.status(200).json(result[0]);
    });
});

// Endpoint to check user role
app.get('/api/user/role', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    pool.query('SELECT role FROM users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.status(200).json({ role: results[0].role });
    });
});

//Konkret felhasznalo lekerdezese
app.get('/users/:id',(req,res)=>{
    const id = req.params.id;

    if(isNaN(id)){
        return res.status(400).json({error: 'Hibas azonosito!'});
    }
    pool.query('SELECT userid, username, password, email, role, balance, balance_last_update, profile_pic FROM users WHERE userid=?', [id],(err,result)=>{
        if(err){
            return res.status(500).json({error: 'Adatbazis hiba!,'});
        }
        if(result.length===0){
            return res.status(404).json({ error: 'Nem talalhato!' });
        }
        return res.status(200).json(result);
    });
});

//Felhasznalo torlese
app.delete('/users/:id',(req,res)=>{
    const id = req.params.id;

    if(isNaN(id)){
        return res.status(400).json({ error: 'Hibas azonosito!' });
    }

    pool.query('DELETE FROM users WHERE id=?', [id],(err,result)=>{
        if(err){
            return res.status(500).json({ error: 'Adatbazis hiba!' });
        }
        if(result.length===0){
            return res.status(404).json({ error: 'Nem talalhato!' });
        }
        return res.status(204).send();
    });
});

//Regisztráció
app.post('/api/register', (req, res) => {
    const {  email, username, psw } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Nem valós email' });
    }

    if (validator.isEmpty(username)) {
        errors.push({ error: 'Töltsd ki a nevet ' });
    }

    if (!validator.isLength(psw, { min: 6 })) {
        errors.push({ error: 'A jelszónak minimum 6 karakterből kell állnia' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    const salt = 10;
    bcrypt.hash(psw, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba a sózáskor' });
        }

        const sql = 'INSERT INTO users (user_id, email, username, password, role, balance, balance_last_update, register_date, profile_pic) VALUES (NULL, ?, ?, ?, "member", 0, NOW(), NOW(), "default.png")';
        pool.query(sql, [email, username, hash], (err2, result) => {
            if (err2) {
                console.log(err2)
                return res.status(500).json({ error: 'Az email már foglalt' });
            }

            res.status(201).json({ message: 'Sikeres regisztráció' });
        });
    });
});

//Belépés
app.post('/api/login', (req, res) => {
    console.log(req)
    const { email, psw } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Add meg az email címet' });
    }

    if (validator.isEmpty(psw)) {
        errors.push({ error: 'Add meg a jelszót' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    const sql = 'SELECT * FROM users WHERE email LIKE ?';
    pool.query(sql, [email], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'A felhasználó nem található' });
        }

        const user = result[0];
        bcrypt.compare(psw, user.password, (err, isMatch) => {
            if (isMatch) {
                const token = jwt.sign(
                    {
                        id: user.user_id
                    },
                    JWT_SECRET,
                    {
                        expiresIn: '1y'
                    }
                );
                
                // Updated cookie settings
                res.cookie('auth_token', token, {
                    httpOnly: false,
                    secure: false,
                    sameSite: 'lax',
                    path: '/',
                    maxAge: 3600000 * 24 * 31 * 12
                });
                
                return res.status(200).json({ message: 'Sikeres bejelentkezés' });
            } else {
                return res.status(401).json({ error: 'Rossz a jelszó' });
            }
        });
    });
});

//Username szerkesztése
app.put('/api/editUsername', authenticateToken, (req, res) => {
    const name = req.body.username;
    const userid = req.user.id;
    console.log('Username to update:', name);
    console.log('User ID:', userid);
    
    // Simpler query
    const sql = 'UPDATE users SET username = ? WHERE user_id = ?';
    
    pool.query(sql, [name, userid], (err, result) => {
        if (err) {
            console.error('SQL Error:', err);  // Add error logging
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }
        
        // Check if any rows were affected
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'No user found with this ID' });
        }
        
        return res.status(200).json({ message: 'Név frissítve' });
    });
});

//Email szerkesztése
app.put('/api/editEmail', authenticateToken, (req, res) => {
    const email = req.body.email;
    const userid = req.user.id;

    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const sql = 'UPDATE users SET email = ? WHERE user_id = ?';
    
    pool.query(sql, [email, userid], (err, result) => {
        if (err) {
            console.error('SQL Error:', err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'No user found with this ID' });
        }
        
        return res.status(200).json({ message: 'Email frissítve' });
    });
});

//Jelszó szerkesztése
app.put('/api/editProfilePsw', authenticateToken, (req, res) => {
    const psw = req.body.psw;
    const userid = req.user.id;

    const salt = 10;

    if (psw === '' && !validator.isLength(psw, { min: 6 })) {
        return res.status(400).json({ error: 'A jelszónak min 6 karakterből kell állnia' });
    }

    bcrypt.hash(psw, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba a sózáskor' });
        }

        const sql = 'UPDATE users SET password = COALESCE(NULLIF(?, ""), password) WHERE user_id = ?';

        pool.query(sql, [hash, userid], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Hiba az SQL-ben' });
            }

            return res.status(200).json({ message: 'Jelszó frissítve ' });
        });
    });
});

//Profilkép szerkesztése
app.put('/api/editProfilePic', authenticateToken, upload.single('profile_pic'), (req, res) => {
    const userid = req.user.id;
    const profile_pic = req.file ? req.file.filename : null;

    const sql = 'UPDATE users SET profile_pic = COALESCE(NULLIF(?, ""), profile_pic) WHERE user_id = ?';

    pool.query(sql, [profile_pic, userid], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        return res.status(200).json({ message: 'Profilkép frissítve ' });
    });
});


//Balance
app.get('/api/balance', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    const sql = 'SELECT balance FROM users WHERE user_id = ?';
    pool.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.status(200).json({ balance: result[0].balance });
    });
});

//Elfelejtett jelszó kérés
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }

    // Check if user exists using promise pool
    promisePool.query('SELECT user_id FROM users WHERE email = ?', [email])
        .then(([users]) => {
            if (users.length === 0) {
                return res.status(404).json({ error: 'No account found with this email' });
            }

            // Generate reset token
            const resetToken = jwt.sign(
                { id: users[0].user_id, purpose: 'password_reset' },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Store reset token
            return promisePool.query(
                'UPDATE users SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE user_id = ?',
                [resetToken, users[0].user_id]
            ).then(() => {
                // Send email
                const resetLink = `http://192.168.10.24:5500/reset-password.html?token=${resetToken}`;
                
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Password Reset Request',
                    html: `
                        <h2>Password Reset Request</h2>
                        <p>Click the link below to reset your password. This link will expire in 1 hour.</p>
                        <a href="${resetLink}">Reset Password</a>
                        <p>If you didn't request this, please ignore this email.</p>
                    `
                };

                return transporter.sendMail(mailOptions);
            });
        })
        .then(() => {
            res.json({ message: 'Password reset email sent' });
        })
        .catch((error) => {
            console.error('Password reset error:', error);
            res.status(500).json({ error: 'Failed to process password reset' });
        });
});

//Elfelejtett jelszó megváltoztatás
app.post('/api/reset-password', (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return res.status(400).json({ error: 'Invalid token' });
    }

    promisePool.query(
        'SELECT user_id FROM users WHERE user_id = ? AND reset_token = ? AND reset_token_expires > NOW()',
        [decoded.id, token]
    )
        .then(([users]) => {
            if (users.length === 0) {
                throw new Error('Invalid or expired reset token');
            }

            return bcrypt.hash(newPassword, 10);
        })
        .then((hashedPassword) => {
            return promisePool.query(
                'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE user_id = ?',
                [hashedPassword, decoded.id]
            );
        })
        .then(() => {
            res.json({ message: 'Password successfully reset' });
        })
        .catch((error) => {
            console.error('Reset password error:', error);
            res.status(500).json({ 
                error: error.message === 'Invalid or expired reset token' 
                    ? error.message 
                    : 'Failed to reset password' 
            });
        });
});

//Fizetés
app.post('/api/create-payment-intent', authenticateToken, async (req, res) => {
    const { amount } = req.body;  // Amount should be in cents (e.g., 1000 for $10.00)

    try {
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'usd',
            automatic_payment_methods: {
                enabled: true,
            },
        });

        res.json({
            clientSecret: paymentIntent.client_secret
        });
    } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).json({ error: 'Failed to create payment' });
    }
});

// Update balance after successful payment
app.post('/api/update-balance', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { amount } = req.body;  // Amount in cents

    const sql = 'UPDATE users SET balance = balance + ? WHERE user_id = ?';
    pool.query(sql, [amount / 100, userId], (err, result) => {
        if (err) {
            console.error('Error updating balance:', err);
            return res.status(500).json({ error: 'Failed to update balance' });
        }
        res.json({ message: 'Balance updated successfully' });
    });
});

// Add this new endpoint
app.get('/api/check-auth', authenticateToken, (req, res) => {
    res.json({ 
        message: 'Authentication successful',
        user: req.user,
        cookies: req.cookies 
    });
});

// Handle bet placement
app.post('/api/place-bet', authenticateToken, async (req, res) => {
    const { amount, type } = req.body;
    const userId = req.user.id;

    try {
        // Insert bet
        const [betResult] = await promisePool.query(
            'INSERT INTO bets (bet) VALUES (?)',
            [amount]
        );

        // Link bet to round
        await promisePool.query(
            'INSERT INTO game_rounds (userid, roundid, betid) VALUES (?, ?, ?)',
            [userId, currentRoundId, betResult.insertId]
        );

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to place bet' });
    }
});















// Add this to your backend routes
app.get('/api/roulette/stats', (req, res) => {
    const queries = {
        // Get color streaks
        colorStreaks: `
            WITH numbered_rows AS (
                SELECT 
                    roundid,
                    winColor,
                    winNumber,
                    ROW_NUMBER() OVER (ORDER BY roundid) as row_num
                FROM rounds
                WHERE winColor IS NOT NULL
            ),
            color_groups AS (
                SELECT 
                    winColor,
                    roundid,
                    row_num,
                    row_num - ROW_NUMBER() OVER (PARTITION BY winColor ORDER BY row_num) as grp
                FROM numbered_rows
            ),
            color_streaks AS (
                SELECT 
                    winColor,
                    COUNT(*) as streak_length,
                    MIN(roundid) as start_roundid,
                    MAX(roundid) as end_roundid
                FROM color_groups
                GROUP BY winColor, grp
                ORDER BY streak_length DESC
            )
            SELECT * FROM color_streaks LIMIT 1
        `,
        
        // Get number streaks
        numberStreaks: `
            WITH numbered_rows AS (
                SELECT 
                    roundid,
                    winColor,
                    winNumber,
                    ROW_NUMBER() OVER (ORDER BY roundid) as row_num
                FROM rounds
                WHERE winNumber IS NOT NULL
            ),
            number_groups AS (
                SELECT 
                    winNumber,
                    roundid,
                    row_num,
                    row_num - ROW_NUMBER() OVER (PARTITION BY winNumber ORDER BY row_num) as grp
                FROM numbered_rows
            ),
            number_streaks AS (
                SELECT 
                    winNumber,
                    COUNT(*) as streak_length,
                    MIN(roundid) as start_roundid,
                    MAX(roundid) as end_roundid
                FROM number_groups
                GROUP BY winNumber, grp
                ORDER BY streak_length DESC
            )
            SELECT * FROM number_streaks LIMIT 1
        `,
        
        // Get color distribution
        colorDistribution: `
            SELECT 
                winColor,
                COUNT(*) as count
            FROM rounds
            WHERE winColor IS NOT NULL
            GROUP BY winColor
        `,
        
        // Get top numbers
        topNumbers: `
            SELECT 
                winNumber,
                COUNT(*) as count
            FROM rounds
            WHERE winNumber IS NOT NULL
            GROUP BY winNumber
            ORDER BY count DESC
            LIMIT 5
        `,
        
        // Get even/odd distribution
        evenOddDistribution: `
            SELECT 
                CASE WHEN winNumber % 2 = 0 THEN 'even' ELSE 'odd' END as type,
                COUNT(*) as count
            FROM rounds
            WHERE winNumber IS NOT NULL
            GROUP BY CASE WHEN winNumber % 2 = 0 THEN 'even' ELSE 'odd' END
        `,
        
        // Get section distribution
        sectionDistribution: `
            SELECT 
                CASE 
                    WHEN winNumber = 0 THEN 'zero'
                    WHEN winNumber <= 12 THEN '1-12'
                    WHEN winNumber <= 24 THEN '13-24'
                    ELSE '25-36'
                END as section,
                COUNT(*) as count
            FROM rounds
            WHERE winNumber IS NOT NULL
            GROUP BY 
                CASE 
                    WHEN winNumber = 0 THEN 'zero'
                    WHEN winNumber <= 12 THEN '1-12'
                    WHEN winNumber <= 24 THEN '13-24'
                    ELSE '25-36'
                END
        `,
        
        // Get high/low distribution
        highLowDistribution: `
            SELECT 
                CASE 
                    WHEN winNumber = 0 THEN 'zero'
                    WHEN winNumber <= 18 THEN 'low'
                    ELSE 'high'
                END as range_type,
                COUNT(*) as count
            FROM rounds
            WHERE winNumber IS NOT NULL
            GROUP BY 
                CASE 
                    WHEN winNumber = 0 THEN 'zero'
                    WHEN winNumber <= 18 THEN 'low'
                    ELSE 'high'
                END
        `
    };

    const stats = {};
    let completedQueries = 0;
    const totalQueries = Object.keys(queries).length;

    // Execute each query
    Object.entries(queries).forEach(([key, query]) => {
        pool.query(query, (err, results) => {
            if (err) {
                console.error(`Error in ${key}:`, err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            stats[key] = results;
            completedQueries++;

            // If all queries are complete, send the response
            if (completedQueries === totalQueries) {
                res.json(stats);
            }
        });
    });
});


























const io = new Server(server, {
    cors: {
        origin: [
            'http://127.0.0.1:5500',
            'http://127.0.0.1:5501',
            'http://192.168.10.24:5500',
            'http://192.168.10.24:3000',
            'http://localhost:5500',
            'http://localhost:3000',
            `http://${HOSTNAME}:3000`
        ],
        methods: ["GET", "POST"],
        credentials: true,
        allowedHeaders: ["Content-Type", "Authorization"]
    }
});

async function getLastTenSpins() {
    try {
        const [spins] = await promisePool.query(`
            SELECT winNumber, winColor 
            FROM rounds 
            WHERE winNumber IS NOT NULL AND winColor IS NOT NULL
            ORDER BY roundid DESC 
            LIMIT 10
        `);
        console.log('Retrieved spins:', spins);
        return spins.reverse();
    } catch (error) {
        console.error('Error fetching last spins:', error);
        return [];
    }
}

let lastTenSpins = [];

let currentBets = {
    red: { total: 0, bets: [] },
    green: { total: 0, bets: [] },
    black: { total: 0, bets: [] }
};






// Socket.IO middleware to authenticate users
io.use((socket, next) => {
    console.log('Socket middleware - checking auth');
    const token = socket.handshake.auth.token;
    console.log('Received token:', token);
    
    if (!token) {
        console.log('No token provided');
        return next(new Error('Authentication error - no token'));
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Token verification failed:', err);
            return next(new Error('Authentication error - invalid token'));
        }
        console.log('Token verified, user:', user);
        socket.user = user;
        next();
    });
});

// Store connected users
const connectedUsers = new Map();

const handleCommands = async (socket, message, pool) => {
    // If message doesn't start with /, treat as regular chat message
    if (!message.startsWith('/')) {
        return false;
    }

    // Get user info from socket (you already have socket.user.id from your auth)
    const userId = socket.user.id;

    // Check if user has admin role
    const [userRows] = await pool.promise().query(
        'SELECT role FROM users WHERE user_id = ?',
        [userId]
    );

    if (!userRows.length || userRows[0].role !== 'ADMIN') {
        socket.emit('error', { message: 'You do not have permission to use commands' });
        return true; // Command was attempted but rejected
    }

    // Split command and arguments
    const args = message.slice(1).split(' ');
    const command = args[0].toLowerCase();

    try {
        switch (command) {
            case 'add':
                if (args.length !== 3) {
                    socket.emit('error', { message: 'Usage: /add USERID AMOUNT' });
                    return true;
                }

                const targetUserId = args[1];
                const amount = parseFloat(args[2]);

                // Validate amount
                if (isNaN(amount) || amount <= 0) {
                    socket.emit('error', { message: 'Amount must be a positive number' });
                    return true;
                }

                // Update user balance in database
                const [updateResult] = await pool.promise().query(
                    'UPDATE users SET balance = balance + ?, balance_last_update = NOW() WHERE user_id = ?',
                    [amount, targetUserId]
                );
                
                if (updateResult.affectedRows === 0) {
                    socket.emit('error', { message: 'User not found' });
                    return true;
                }
                
                const [targetUser] = await pool.promise().query(
                    'SELECT user_id, balance FROM users WHERE user_id = ?',
                    [targetUserId]
                );

                if (targetUser.length > 0) {
                    // Emit balance update to specific user if they're online
                    const targetSocketId = connectedUsers.get(parseInt(targetUserId));
                    if (targetSocketId) {
                        io.to(targetSocketId).emit('balance_update', {
                            balance: targetUser[0].balance
                        });
                    }
                }

                // Notify admin that command was successful
                socket.emit('commandResponse', {
                    message: `Successfully added ${amount} to user ${targetUserId}'s balance`
                });
                break;

            default:
                socket.emit('error', { message: 'Unknown command' });
        }
    } catch (error) {
        console.error('Command error:', error);
        socket.emit('error', { message: 'An error occurred while executing the command' });
    }

    return true; // Command was handled
};


io.on('connection', (socket) => {
    console.log('User connected:', socket.user.id);
    connectedUsers.set(socket.user.id, socket.id);

    // Chat functionality
    const loadMessages = `
        SELECT m.*, u.username, u.profile_pic 
        FROM messages m 
        JOIN users u ON m.user_id = u.user_id 
        ORDER BY created_at DESC 
        LIMIT 10
    `;
    
    pool.query(loadMessages, (err, results) => {
        if (err) {
            console.error('Error loading messages:', err);
            return;
        }
        socket.emit('load_messages', results.reverse());
    });

    socket.on('send_message', async (messageData) => {
        const userId = socket.user.id;
        const message = messageData.message.trim();
        if (!message) return;

        try {
            // Handle potential commands first
            const wasCommand = await handleCommands(socket, message, pool);
            
            // If it wasn't a command, proceed with normal message handling
            if (!wasCommand) {
                // Save message to database
                const sql = 'INSERT INTO messages (user_id, message) VALUES (?, ?)';
                pool.query(sql, [userId, message], (err, result) => {
                    if (err) {
                        console.error('Error saving message:', err);
                        return;
                    }

                    // Get the saved message with user info
                    const getMessageSql = `
                        SELECT m.*, u.username, u.profile_pic 
                        FROM messages m 
                        JOIN users u ON m.user_id = u.user_id 
                        WHERE m.message_id = ?
                    `;
                    
                    pool.query(getMessageSql, [result.insertId], (err, results) => {
                        if (err || results.length === 0) {
                            console.error('Error retrieving saved message:', err);
                            return;
                        }

                        const savedMessage = results[0];
                        io.emit('new_message', savedMessage);
                    });
                });
            }
        } catch (error) {
            console.error('Message handling error:', error);
            socket.emit('error', { message: 'An error occurred while processing your message' });
        }
    });

    socket.emit('bets_update', currentBets);

    //timer
    socket.on('request_game_state', async () => {
        const lastSpins = await getLastTenSpins();
        socket.emit('update_previous_spins', { spins: lastSpins });
        if (currentGameState.inProgress) {
            socket.emit('round_start', {
                roundId: currentGameState.roundId,
                timeLeft: Math.ceil((roundEndTime - Date.now()) / 1000)
            });
        }
    });

    socket.on('request_current_bets', () => {
        // Send current bets to the requesting client
        socket.emit('bets_update', currentBets);
    });

    // Roulette game functionality
    socket.on('place_bet', async (betData) => {
        try {
            const userId = socket.user.id;
            const { amount, type } = betData;
    
            // Check user's balance first
            const [userRows] = await promisePool.query(
                'SELECT balance, username, profile_pic FROM users WHERE user_id = ?',
                [userId]
            );
            
            if (userRows[0].balance < amount) {
                return socket.emit('bet_placed', {
                    success: false,
                    error: 'Insufficient balance'
                });
            }
    
            // Check if user already has a bet of this type
            const existingBetIndex = currentBets[type].bets.findIndex(bet => bet.userId === userId);
    
            if (existingBetIndex !== -1) {
                // Update existing bet
                currentBets[type].total += amount;
                currentBets[type].bets[existingBetIndex].amount += amount;
            } else {
                // Create new bet
                const betInfo = {
                    userId: userId,
                    username: userRows[0].username,
                    profilePic: userRows[0].profile_pic,
                    amount: amount
                };
                currentBets[type].bets.push(betInfo);
                currentBets[type].total += amount;
            }
    
            // Emit updated bets to all clients
            io.emit('bets_update', currentBets);
    
            // Deduct balance
            await promisePool.query(
                'UPDATE users SET balance = balance - ? WHERE user_id = ?',
                [amount, userId]
            );
    
            // Insert bet record
            const [betResult] = await promisePool.query(
                'INSERT INTO bets (bet) VALUES (?)',
                [amount]
            );
    
            // Link bet to round
            await promisePool.query(
                'INSERT INTO game_rounds (userid, roundid, betid, bet_type) VALUES (?, ?, ?, ?)',
                [userId, currentRoundId, betResult.insertId, type]
            );
    
            socket.emit('bet_placed', {
                success: true,
                amount,
                type
            });
    
            // Emit updated balance
            socket.emit('balance_update', {
                balance: userRows[0].balance - amount
            });
        } catch (error) {
            socket.emit('bet_placed', {
                success: false,
                error: error.message
            });
        }
    });

    socket.on('disconnect', () => {
        connectedUsers.delete(socket.user.id);
        console.log('User disconnected:', socket.user.id);
    });
});








// Global variables for game state
let currentRoundId = null;
let gameInterval = null;
let roundEndTime = null;
let currentGameState = {
    roundId: null,
    timeLeft: 15,
    inProgress: false,
    isSpinning: false,  // Added to track spinning state
    spinStartTime: null // Added to track when spin started
};

// Function to start a new round
async function startNewRound(pool) {
    try {
        // Insert new game
        // const [gameResult] = await promisePool.query(
        //     'INSERT INTO games (gamename, description) VALUES ("roulette", "")'
        // );
        // const gameId = gameResult.insertId;
 
        // Insert new round
        const [roundResult] = await promisePool.query(
            'INSERT INTO rounds (gameid) VALUES (1)'
        );
        currentRoundId = roundResult.insertId;

        const lastSpins = await getLastTenSpins();
       io.emit('update_previous_spins', { spins: lastSpins });
        
        currentGameState = {
            roundId: currentRoundId,
            timeLeft: 15,
            inProgress: true,
            isSpinning: false,
            spinStartTime: null
        };
        roundEndTime = Date.now() + 15000;
 
        // Start countdown timer
        const countdownInterval = setInterval(() => {
            currentGameState.timeLeft = Math.ceil((roundEndTime - Date.now()) / 1000);

            if (currentGameState.timeLeft <= 0) {
                clearInterval(countdownInterval);
                currentGameState.isSpinning = true;
                currentGameState.spinStartTime = Date.now();
                io.emit('spin_start'); // Optional: notify clients that spinning has started
            }

            io.emit('time_update', { timeLeft: currentGameState.timeLeft,
                isSpinning: currentGameState.isSpinning });
        }, 1000);
 
        // Emit initial round start
        io.emit('round_start', { 
            roundId: currentRoundId, 
            timeLeft: 15,
            isSpinning: false
        });
 
        // Schedule round end
        setTimeout(() => {
            clearInterval(countdownInterval);
            endRound(pool);
        }, 15000);
 
        currentBets = {
            red: { total: 0, bets: [] },
            green: { total: 0, bets: [] },
            black: { total: 0, bets: [] }
        };

    } catch (error) {
        console.error('Error starting new round:', error);
    }
}

// Function to end round and process bets
async function endRound(pool) {
    try {
        currentGameState.isSpinning = true;
        currentGameState.spinStartTime = Date.now();

        const result = Math.floor(Math.random() * 15);
        const winColor = result === 0 ? 'green' : 
                       [1,2,3,4,5,6,7].includes(result) ? 'red' : 'black';

        await promisePool.query(
           'UPDATE rounds SET winColor = ?, winNumber = ? WHERE roundid = ?',
           [winColor, result, currentRoundId]
        );

        // const lastSpins = await getLastTenSpins();
        // io.emit('update_previous_spins', { spins: lastSpins });

        const [bets] = await promisePool.query(`
            SELECT gr.userid, gr.betid, b.bet, u.balance, gr.bet_type as type
            FROM game_rounds gr
            JOIN bets b ON gr.betid = b.betid
            JOIN users u ON gr.userid = u.user_id
            WHERE gr.roundid = ?`,
            [currentRoundId]
        );

        const userWinnings = new Map();

        for (const bet of bets) {
            const isWin = (bet.type === 'green' && result === 0) ||
                         (bet.type === 'red' && [1,2,3,4,5,6,7].includes(result)) ||
                         (bet.type === 'black' && [8,9,10,11,12,13,14].includes(result));
 
            if (isWin) {
                const multiplier = bet.type === 'green' ? 14 : 2;
                const winAmount = bet.bet * multiplier;
                
                const currentWinnings = userWinnings.get(bet.userid) || 0;
                userWinnings.set(bet.userid, currentWinnings + winAmount);
            }
        }

        // Record payouts and update balances
       for (const [userId, totalWinnings] of userWinnings) {
        await promisePool.query(
            'INSERT INTO payouts (roundid, userid, payout) VALUES (?, ?, ?)',
            [currentRoundId, userId, totalWinnings]
        );

        await promisePool.query(
            'UPDATE users SET balance = balance + ? WHERE user_id = ?',
            [totalWinnings, userId]
        );
        
    }
        io.emit('round_end', { result, winColor, isSpinning: true });
        setTimeout(() => {
            // Reset game state before starting new round
            currentGameState = {
                roundId: null,
                timeLeft: 15,
                inProgress: false,
                isSpinning: false,
                spinStartTime: null
            };
            
            startNewRound(pool);
        }, 9000);
        io.emit('bets_update', currentBets); // Emit empty bets to clear displays
    } catch (error) {
        console.error('Error ending round:', error);
                // Reset game state even if there's an error

        currentGameState = {
            roundId: null,
            timeLeft: 15,
            inProgress: false,
            isSpinning: false,
            spinStartTime: null
        };
    }
}

// Start the game loop when server starts
function initGameLoop(pool) {
    startNewRound(pool);
}

// Initialize game when server starts
initGameLoop(pool);



app.get("/",(req,res) => {
    res.send("teszt")
});


app.listen(PORT, () =>{
    console.log(`IP: ${HOSTNAME} - Port:${PORT}`)
});