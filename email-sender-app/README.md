# Email Sender App

This is a simple web application to send emails to multiple recipients from your Gmail account using an app password for secure authentication.

## Setup Instructions

### 1. Enable 2-Factor Authentication (2FA)
If you haven't already, enable 2FA on your Gmail account:
1. Go to your Google Account settings.
2. Navigate to "Security" > "Signing in to Google".
3. Turn on 2-Step Verification.

### 2. Generate App Password
1. Go to your Google Account settings.
2. Navigate to "Security" > "Signing in to Google" > "App passwords".
3. Sign in if prompted.
4. Select "Mail" and "Other (custom name)" from the dropdowns.
5. Enter a name like "Email Sender App".
6. Click "Generate".
7. Copy the 16-character password (ignore spaces).

### 3. Environment Variables
1. Copy `.env.example` to `.env`.
2. Fill in the values:
   - `EMAIL_USER`: Your Gmail address.
   - `EMAIL_PASS`: The app password you generated (16 characters, no spaces).

### 4. Install Dependencies and Run
```bash
npm install
npm start
```

Open http://localhost:3000 in your browser, fill the form, and send emails.

## Features

- Send to multiple emails (comma-separated).
- Attach files.
- Secure authentication with app password.
