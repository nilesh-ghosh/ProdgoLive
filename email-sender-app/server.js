const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const multer = require('multer');
const path = require('path');
const axios = require('axios');
const { TIMEOUT } = require('dns');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const logFile = 'server.log';
const MailComposer = require('mailcomposer');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const port = 3000;

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { recursive: true });
}

// Initialize SQLite database
const db = new sqlite3.Database('users.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    gmail_client_id TEXT,
    gmail_client_secret TEXT,
    gmail_refresh_token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Note: created_at column is included in CREATE TABLE. If existing DB lacks it, delete users.db to recreate.
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set secure: true for HTTPS
}));

// Rate limiter for signup
const signupLimiter = rateLimit({
  windowMs: 2147483647, // Max allowed 32-bit signed int (~24.8 days)
  max: 2, // 1 signup per IP
  message: 'Signup limit reached for this IP.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/');
}

const OAuth2 = google.auth.OAuth2;

// Function to get OAuth2 client for Gmail API
async function getAuth(userId) {
  const user = await new Promise((resolve, reject) => {
    db.get('SELECT username, gmail_client_id, gmail_client_secret, gmail_refresh_token FROM users WHERE id = ?', [userId], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

  if (!user || !user.gmail_client_id || !user.gmail_client_secret || !user.gmail_refresh_token) {
    throw new Error('OAuth2 credentials not set for user.');
  }

  const oauth2Client = new OAuth2(
    user.gmail_client_id,
    user.gmail_client_secret,
    'https://developers.google.com/oauthplayground' // Redirect URL
  );

  oauth2Client.setCredentials({
    refresh_token: user.gmail_refresh_token
  });

  await oauth2Client.getAccessToken(); // Ensure access token is available

  return oauth2Client;
}

async function verifyEmail(email) {
  if (!process.env.GMAIL_VERIFIER_API_KEY) {
    // Skip verification if API key not set
    return { success: true, result: { valid: true } };
  }
  try {
    const response = await axios.post(
      'https://api.validkit.com/api/v1/verify',
      { email },
      {
        headers: {
          'X-API-Key': process.env.GMAIL_VERIFIER_API_KEY,
          'Content-Type': 'application/json'
        }
      }
    );
    // Log the full response for debugging
    const logEntry = `${new Date().toISOString()} - Verified email: ${email} - Response: ${JSON.stringify(response.data)}\n`;
    fs.appendFileSync(logFile, logEntry);

    // Handle possible response variations
    if (response.data.success == true && response.data.result.valid == true) {
      return response.data;
    } else {
      return null;
    }
  } catch (error) {
    const errorLog = `${new Date().toISOString()} - Error verifying email: ${email} - ${error.message}\n`;
    fs.appendFileSync(logFile, errorLog);
    console.error('Error verifying email:', error.message);
    return null;
  }
}

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', signupLimiter, (req, res) => {
  let { username, password } = req.body;

  // Sanitize inputs
  username = username.trim().toLowerCase();
  password = password.trim();

  // Basic validation
  if (!username || !password) {
    return res.status(400).send('Username and password required.');
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(username)) {
    return res.status(400).send('Invalid email format.');
  }

  // Password strength validation
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).send('Password must be at least 8 characters with uppercase, lowercase, number, and special character.');
  }

  // Check for dangerous characters in username (basic)
  if (/[<>\"';&]/.test(username)) {
    return res.status(400).send('Invalid characters in username.');
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).send('Username already exists. <a href="/signup">Try again</a>');
      }
      return res.status(500).send('Database error.');
    }
    res.redirect('/');
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).send('Invalid credentials. <a href="/">Try again</a>');
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout error.');
    }
    res.redirect('/');
  });
});

app.get('/sender', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sender.html'));
});

app.get('/settings', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});

app.post('/update-env', requireAuth, (req, res) => {
  const { email_user, gmail_client_id, gmail_client_secret, gmail_refresh_token } = req.body;

  db.run('UPDATE users SET gmail_client_id = ?, gmail_client_secret = ?, gmail_refresh_token = ? WHERE id = ?',
    [gmail_client_id, gmail_client_secret, gmail_refresh_token, req.session.userId], function(err) {
    if (err) {
      return res.status(500).send('Database error.');
    }
    res.send('Settings updated successfully. Changes applied immediately. <a href="/sender">Back to Sender</a>');
  });
});

// Route to handle form submission
app.post('/send-email', requireAuth, upload.single('attachment'), async (req, res) => {
  const { to, subject, content } = req.body;
  const toEmails = to.split(',').map(email => email.trim()).filter(email => email);

  if (!toEmails.length || !subject || !content) {
    return res.status(400).send('Missing required fields: To, Subject, or Content.');
  }

  let successCount = 0;
  let errors = [];
  // Helper function to introduce delay
  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  for (const email of toEmails) {
    // Verify email format and domain using ValidKit API
    const verificationResult = await verifyEmail(email);
    if (!verificationResult || !(verificationResult.success === true && verificationResult.result && verificationResult.result.valid === true)) {
      errors.push('Invalid or unverified email (format/domain): ' + email);
      continue;
    }

    const mailOptions = {
      from: req.session.username,
      to: email,
      subject: subject,
      text: content,
      attachments: req.file ? [
        {
          filename: req.file.originalname,
          path: req.file.path
        }
      ] : []
    };

    try {
      const auth = await getAuth(req.session.userId);
      const gmail = google.gmail({ version: 'v1', auth });

      const mail = new MailComposer(mailOptions);
      const message = await new Promise((resolve, reject) => {
        mail.build((err, message) => {
          if (err) reject(err);
          else resolve(message);
        });
      });

      const raw = message.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      await gmail.users.messages.send({
        userId: 'me',
        resource: { raw }
      });

      console.log('Email sent to ' + email);
      successCount++;
    } catch (error) {
      console.error('Error sending email to ' + email + ':', error);
      errors.push('Failed to send to ' + email + ': ' + error.message);
    }
    await sleep(5000); // 5 seconds delay
  }

  if (errors.length > 0) {
    res.send(`Emails sent successfully to ${successCount} recipient(s). <br> Errors: ${errors.join('<br>')}`);
  } else {
    res.send(`Email sent successfully to ${successCount} recipient(s)!`);
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
