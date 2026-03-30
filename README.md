# Secure_Login_System
A full-featured Flask web application demonstrating enterprise-level security practices including JWT authentication, TOTP 2FA, credential stuffing protection, and runtime anomaly detection.
##  Features

###  Authentication & Security
- **Secure user registration & login** with password hashing (Werkzeug)
- **Rate limiting** (Flask-Limiter) to prevent credential stuffing attacks
- **Two-Factor Authentication (2FA)** using TOTP + QR code setup
- **JWT-based authentication** with access & refresh tokens
- **Account blocking** after consecutive failed login attempts
- **Secure session management** with IP & User-Agent tracking

###  Runtime Anomaly Detection
- Detects **multiple failed logins** from same IP
- Identifies **credential stuffing** attempts
- Detects **account enumeration** attacks
- Real-time anomaly logging and severity classification

###  Advanced Admin Dashboard
- Real-time statistics (users, logins, anomalies, sessions)
- Live charts (Login trends + Anomaly types)
- Users management (block/unblock)
- Full login attempt history
- Anomaly detection & patterns by IP
- One-click anomaly resolution

###  Modern UI
- Clean, responsive Tailwind CSS + Font Awesome interface
- Separate **User Dashboard** and **Admin Dashboard**
- Mobile-friendly design

---

##  Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite + SQLAlchemy
- **Authentication**: Flask-JWT-Extended
- **Rate Limiting**: Flask-Limiter
- **2FA**: pyotp + qrcode
- **Frontend**: Tailwind CSS, Chart.js, Font Awesome
- **Security**: Werkzeug password hashing, secure token generation

---

##  Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/secure-logging-system.git
cd secure-logging-system
 ```
### 2. Create virtual environment (recommended)
```bash
python -m venv venv
 ```
### Windows
 ```
venv\Scripts\activate
 ```
### macOS / Linux
 ```
source venv/bin/activate
 ```
### 3. Install dependencies
 ```bash
 pip install -r requirements.txt
  ```
### 4. Run setup (creates database + default admin)
 ```bash
python setup.py
  ```
### 5. Start the application
 ```bash
 python app.py
 ```
🔑 Default Admin Credentials
Username: admin
Password: admin123
⚠️ IMPORTANT: Change this password immediately in production!

##  Project Structure

secure-login-system/ssd
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── setup.py                  # Database initialization
├── templates/
│   ├── admin_dashboard.html
│   ├── admin_login.html
│   ├── user_dashboard.html
│   ├── user_login.html
│   └── user_register.html
└── secure_logging.db         # Database (auto-generated)

<img width="847" height="590" alt="image" src="https://github.com/user-attachments/assets/e65e3bf2-004e-496f-8ba7-7a68964f4379" />

<img width="910" height="338" alt="image" src="https://github.com/user-attachments/assets/a682bf4c-690d-48b5-ab33-2d6a41ba8ac1" />

<img width="1159" height="648" alt="image" src="https://github.com/user-attachments/assets/b61e1829-e6aa-4a7e-adad-d58e5e4becaf" />

<img width="1513" height="880" alt="image" src="https://github.com/user-attachments/assets/6a2187b1-2949-40ed-8f10-36491286a200" />


##  Project Purpose
This project was developed as a Secure Software Design academic project to demonstrate:

- Defense against common web attacks
- Secure coding practices
- Real-time security monitoring
- Modern authentication flows
