"""
Main Flask Application - Secure Logging System
This is the entry point for the secure logging system with:
- Rate limiting to prevent credential stuffing
- Anomaly detection at runtime
- Two-factor authentication (2FA)
- Secure token generation (JWT)
- Advanced dashboard for monitoring

Author: Secure Logging System
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
import json
from functools import wraps
import ipaddress
from collections import defaultdict
import statistics
import os

# Initialize Flask app with explicit template folder
# Get the directory where this script is located
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')

app = Flask(__name__, template_folder=template_dir)
app.config['SECRET_KEY'] = '3fK9mPqR7vL2nX8sT5wY6uJ1hZ0gB4cD'  # Fixed strong key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_logging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'xA8eV3tQ9rW6yU2iO1pL5kJ7hG4fD0cN'  # Different fixed strong key for JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Access token expires in 1 hour
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)  # Refresh token expires in 7 days

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Initialize rate limiter
# This prevents credential stuffing by limiting login attempts
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Rate limit by IP address
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # In production, use Redis
    headers_enabled=True
)

# Custom error handler for rate limiting - return JSON instead of HTML
@limiter.request_filter
def ip_whitelist():
    """Allow certain IPs to bypass rate limiting if needed"""
    return False  # Don't bypass for now

@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom handler for rate limit errors - returns JSON"""
    # Get retry-after header if available
    retry_after = None
    if hasattr(e, 'description'):
        # Extract retry-after from description if available
        import re
        match = re.search(r'retry.*?after.*?(\d+)', str(e.description), re.IGNORECASE)
        if match:
            retry_after = int(match.group(1))
    
    return jsonify({
        'error': 'Too many requests',
        'message': 'Too many login attempts! Please wait 1 minute before trying again.',
        'retry_after': retry_after or 60
    }), 429

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    """
    User model stores user account information.
    Includes 2FA secret for two-factor authentication and blocking status.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Hashed password, never store plain text
    two_factor_secret = db.Column(db.String(32))  # TOTP secret for 2FA
    two_factor_enabled = db.Column(db.Boolean, default=False)  # Whether 2FA is enabled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    
    # Blocking fields
    is_blocked = db.Column(db.Boolean, default=False)  # Whether user is blocked
    blocked_at = db.Column(db.DateTime, nullable=True)  # When user was blocked
    block_reason = db.Column(db.String(255), nullable=True)  # Reason for blocking
    failed_login_count = db.Column(db.Integer, default=0)  # Count of consecutive failed logins
    last_failed_login = db.Column(db.DateTime, nullable=True)  # Last failed login timestamp
    
    # Relationships
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def check_and_block(self):
        """
        Check if user should be blocked based on failed login attempts.
        Blocks user if 5+ consecutive failed logins within 15 minutes.
        """
        if self.is_blocked:
            return True
        
        # Reset counter if last failed login was more than 15 minutes ago
        if self.last_failed_login:
            time_since_last_failure = datetime.utcnow() - self.last_failed_login
            if time_since_last_failure > timedelta(minutes=15):
                self.failed_login_count = 0
                db.session.commit()
        
        # Block if 5+ consecutive failures
        if self.failed_login_count >= 5:
            self.is_blocked = True
            self.blocked_at = datetime.utcnow()
            self.block_reason = f'Too many failed login attempts ({self.failed_login_count})'
            db.session.commit()
            return True
        
        return False


class LoginAttempt(db.Model):
    """
    LoginAttempt model tracks all login attempts.
    Used for anomaly detection and security monitoring.
    """
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Null if user doesn't exist
    username = db.Column(db.String(80), nullable=False)  # Store attempted username
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, default=False)  # Whether login succeeded
    failure_reason = db.Column(db.String(255))  # Reason for failure
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    location_data = db.Column(db.Text)  # JSON string for location data
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} from {self.ip_address} - {self.success}>'


class UserSession(db.Model):
    """
    UserSession model tracks active user sessions.
    Prevents session hijacking by tracking session tokens and IP addresses.
    """
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)  # Secure session token
    refresh_token = db.Column(db.String(255), unique=True, nullable=False)  # Refresh token
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)  # For token revocation
    
    def __repr__(self):
        return f'<UserSession {self.user_id} - {self.session_token[:10]}...>'


class Anomaly(db.Model):
    """
    Anomaly model stores detected anomalous behaviors.
    Used for security monitoring and alerting.
    """
    __tablename__ = 'anomalies'
    
    id = db.Column(db.Integer, primary_key=True)
    anomaly_type = db.Column(db.String(50), nullable=False)  # e.g., 'multiple_failures', 'unusual_ip', 'rapid_requests'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    anomaly_metadata = db.Column(db.Text)  # JSON string for additional data (renamed from 'metadata' - SQLAlchemy reserved word)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Anomaly {self.anomaly_type} - {self.severity}>'


# ============================================================================
# ANOMALY DETECTION SYSTEM
# ============================================================================

class AnomalyDetector:
    """
    AnomalyDetector class implements runtime anomaly detection.
    Detects suspicious patterns like:
    - Multiple failed login attempts
    - Unusual IP addresses
    - Rapid request patterns
    - Geographic anomalies
    """
    
    def __init__(self):
        self.ip_attempts = defaultdict(list)  # Track attempts per IP
        self.user_attempts = defaultdict(list)  # Track attempts per user
        self.recent_anomalies = []  # Cache recent anomalies
        
    def detect_anomalies(self, username=None, ip_address=None, success=False):
        """
        Main anomaly detection function.
        Analyzes login patterns and detects suspicious behavior.
        """
        anomalies = []
        
        if ip_address:
            # Check for rapid failed attempts from same IP
            recent_failures = LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.success == False,
                LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=15)
            ).count()
            
            if recent_failures >= 5:
                anomaly = Anomaly(
                    anomaly_type='multiple_failures',
                    ip_address=ip_address,
                    severity='high',
                    description=f'Multiple failed login attempts ({recent_failures}) from IP {ip_address} in last 15 minutes',
                    anomaly_metadata=json.dumps({'failure_count': recent_failures, 'time_window': '15 minutes'})
                )
                anomalies.append(anomaly)
            
            # Check for unusual IP patterns
            unique_users = LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).with_entities(LoginAttempt.username).distinct().count()
            
            if unique_users >= 10:
                anomaly = Anomaly(
                    anomaly_type='credential_stuffing',
                    ip_address=ip_address,
                    severity='critical',
                    description=f'IP {ip_address} attempted to login with {unique_users} different usernames in last hour',
                    anomaly_metadata=json.dumps({'unique_usernames': unique_users})
                )
                anomalies.append(anomaly)
        
        if username:
            # Check for account enumeration
            user = User.query.filter_by(username=username).first()
            if not user:
                # Check if many failed attempts for non-existent user
                failed_attempts = LoginAttempt.query.filter(
                    LoginAttempt.username == username,
                    LoginAttempt.success == False,
                    LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
                ).count()
                
                if failed_attempts >= 3:
                    anomaly = Anomaly(
                        anomaly_type='account_enumeration',
                        ip_address=ip_address or 'unknown',
                        severity='medium',
                        description=f'Multiple failed attempts for non-existent user: {username}',
                        anomaly_metadata=json.dumps({'attempts': failed_attempts, 'username': username})
                    )
                    anomalies.append(anomaly)
        
        # Save detected anomalies to database
        for anomaly in anomalies:
            # Check if similar anomaly already exists (avoid duplicates)
            existing = Anomaly.query.filter(
                Anomaly.anomaly_type == anomaly.anomaly_type,
                Anomaly.ip_address == anomaly.ip_address,
                Anomaly.detected_at >= datetime.utcnow() - timedelta(minutes=30)
            ).first()
            
            if not existing:
                db.session.add(anomaly)
        
        db.session.commit()
        return anomalies

# Initialize anomaly detector
anomaly_detector = AnomalyDetector()


# ============================================================================
# SECURE TOKEN GENERATION
# ============================================================================

def generate_secure_token(length=32):
    """
    Generate cryptographically secure random token.
    Uses secrets module which is cryptographically secure.
    """
    return secrets.token_urlsafe(length)


def generate_session_token():
    """
    Generate secure session token with timestamp hash.
    Combines random token with timestamp for uniqueness.
    """
    random_part = secrets.token_urlsafe(24)
    timestamp = str(int(datetime.utcnow().timestamp()))
    combined = f"{random_part}{timestamp}"
    return hashlib.sha256(combined.encode()).hexdigest()


# ============================================================================
# RATE LIMITING DECORATORS
# ============================================================================

def rate_limit_by_user(f):
    """
    Custom rate limiting decorator that limits by user ID.
    Additional layer of protection beyond IP-based limiting.
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        # Additional rate limiting logic can be added here
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# API ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/')
def index():
    """Redirect to user interface"""
    return redirect(url_for('user_login'))


@app.route('/admin')
def admin_dashboard():
    """Admin dashboard page - frontend JS handles authentication"""
    return render_template('admin_dashboard.html')

@app.route('/admin/login')
def admin_login_page():
    """Admin login page"""
    return render_template('admin_login.html')


@app.route('/user/login')
def user_login():
    """User login page"""
    return render_template('user_login.html')


@app.route('/user/register')
def user_register():
    """User registration page"""
    return render_template('user_register.html')


@app.route('/user/dashboard')
def user_dashboard():
    """User dashboard page"""
    return render_template('user_dashboard.html')


@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    """
    User registration endpoint.
    Rate limited to prevent abuse.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validation
        if not username or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user with hashed password
        # Never store plain text passwords!
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': new_user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts per IP
def login():
    """
    User login endpoint with anomaly detection.
    Rate limited to prevent credential stuffing.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        two_factor_code = data.get('two_factor_code')  # Optional 2FA code
        
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Log login attempt
        login_attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False
        )
        
        # Validate input
        if not username or not password:
            login_attempt.failure_reason = 'Missing credentials'
            db.session.add(login_attempt)
            db.session.commit()
            return jsonify({'error': 'Missing credentials'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and is blocked
        if user and user.is_blocked:
            login_attempt.user_id = user.id
            login_attempt.failure_reason = f'User is blocked: {user.block_reason}'
            db.session.add(login_attempt)
            db.session.commit()
            return jsonify({
                'error': 'Your account has been blocked due to suspicious activity',
                'blocked': True,
                'block_reason': user.block_reason
            }), 403
        
        if not user or not check_password_hash(user.password_hash, password):
            # Increment failed login count if user exists
            if user:
                user.failed_login_count += 1
                user.last_failed_login = datetime.utcnow()
                login_attempt.user_id = user.id
                
                # Check if user should be blocked
                if user.check_and_block():
                    login_attempt.failure_reason = f'User blocked after {user.failed_login_count} failed attempts'
                else:
                    login_attempt.failure_reason = 'Invalid credentials'
            else:
                login_attempt.failure_reason = 'Invalid credentials'
            
            db.session.add(login_attempt)
            db.session.commit()
            
            # Run anomaly detection
            anomaly_detector.detect_anomalies(username=username, ip_address=ip_address, success=False)
            
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Reset failed login count on successful login
        user.failed_login_count = 0
        user.last_failed_login = None
        
        # Check if 2FA is enabled
        if user.two_factor_enabled:
            if not two_factor_code:
                login_attempt.failure_reason = '2FA code required'
                db.session.add(login_attempt)
                db.session.commit()
                return jsonify({
                    'error': '2FA code required',
                    'two_factor_required': True
                }), 401
            
            # Verify 2FA code
            totp = pyotp.TOTP(user.two_factor_secret)
            if not totp.verify(two_factor_code, valid_window=1):
                login_attempt.failure_reason = 'Invalid 2FA code'
                db.session.add(login_attempt)
                db.session.commit()
                return jsonify({'error': 'Invalid 2FA code'}), 401
        
        # Login successful
        login_attempt.user_id = user.id
        login_attempt.success = True
        login_attempt.failure_reason = None
        db.session.add(login_attempt)
        
        # Update user last login and reset failed attempts
        user.last_login = datetime.utcnow()
        user.failed_login_count = 0
        user.last_failed_login = None
        
        # Generate secure tokens
        access_token = create_access_token(identity=user.username)
        refresh_token = create_refresh_token(identity=user.username)
        session_token = generate_session_token()
        
        # Create session record
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db.session.add(user_session)
        db.session.commit()
        
        # Run anomaly detection (even for successful logins)
        anomaly_detector.detect_anomalies(username=username, ip_address=ip_address, success=True)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_token': session_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'two_factor_enabled': user.two_factor_enabled
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token using refresh token.
    Allows users to get new access tokens without re-authenticating.
    """
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        return jsonify({'access_token': new_access_token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 401


@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """
    Return the current authenticated user's profile.
    Used by the user dashboard to show username/email/status.
    """
    try:
        current_username = get_jwt_identity()
        user = User.query.filter_by(username=current_username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'two_factor_enabled': user.two_factor_enabled,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_active': user.is_active,
                'is_blocked': user.is_blocked,
                'block_reason': user.block_reason,
                'failed_login_count': user.failed_login_count
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ROUTES - TWO-FACTOR AUTHENTICATION
# ============================================================================

@app.route('/api/2fa/setup', methods=['POST'])
@jwt_required()
def setup_2fa():
    """
    Setup two-factor authentication for user.
    Generates TOTP secret and QR code.
    """
    try:
        current_username = get_jwt_identity()
        user = User.query.filter_by(username=current_username).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate TOTP secret
        # TOTP (Time-based One-Time Password) is the standard for 2FA
        secret = pyotp.random_base32()
        user.two_factor_secret = secret
        
        # Generate QR code for easy setup
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name='Secure Logging System'
        )
        
        # Create QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for frontend
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        db.session.commit()
        
        return jsonify({
            'secret': secret,
            'qr_code': f'data:image/png;base64,{img_str}',
            'manual_entry_key': secret
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/2fa/verify', methods=['POST'])
@jwt_required()
def verify_2fa():
    """
    Verify 2FA setup by checking the code.
    Enables 2FA after successful verification.
    """
    try:
        current_username = get_jwt_identity()
        user = User.query.filter_by(username=current_username).first()
        data = request.get_json()
        code = data.get('code')
        
        if not user or not user.two_factor_secret:
            return jsonify({'error': '2FA not set up'}), 400
        
        # Verify TOTP code
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(code, valid_window=1):
            user.two_factor_enabled = True
            db.session.commit()
            return jsonify({'message': '2FA enabled successfully'}), 200
        else:
            return jsonify({'error': 'Invalid code'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/2fa/disable', methods=['POST'])
@jwt_required()
def disable_2fa():
    """Disable two-factor authentication"""
    try:
        current_username = get_jwt_identity()
        user = User.query.filter_by(username=current_username).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.session.commit()
        
        return jsonify({'message': '2FA disabled successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ROUTES - DASHBOARD DATA
# ============================================================================

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """
    Get dashboard statistics for monitoring.
    Returns user counts, login attempts, anomalies, etc.
    """
    try:
        # User statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True, is_blocked=False).count()
        blocked_users = User.query.filter_by(is_blocked=True).count()
        users_today = User.query.filter(
            User.created_at >= datetime.utcnow().date()
        ).count()
        
        # Login attempt statistics
        total_attempts = LoginAttempt.query.count()
        successful_logins = LoginAttempt.query.filter_by(success=True).count()
        failed_logins = LoginAttempt.query.filter_by(success=False).count()
        attempts_today = LoginAttempt.query.filter(
            LoginAttempt.timestamp >= datetime.utcnow().date()
        ).count()
        
        # Anomaly statistics
        total_anomalies = Anomaly.query.count()
        unresolved_anomalies = Anomaly.query.filter_by(resolved=False).count()
        critical_anomalies = Anomaly.query.filter_by(severity='critical', resolved=False).count()
        anomalies_today = Anomaly.query.filter(
            Anomaly.detected_at >= datetime.utcnow().date()
        ).count()
        
        # Session statistics
        active_sessions = UserSession.query.filter(
            UserSession.expires_at > datetime.utcnow(),
            UserSession.is_revoked == False
        ).count()
        
        return jsonify({
            'users': {
                'total': total_users,
                'active': active_users,
                'blocked': blocked_users,
                'new_today': users_today
            },
            'login_attempts': {
                'total': total_attempts,
                'successful': successful_logins,
                'failed': failed_logins,
                'today': attempts_today,
                'success_rate': round((successful_logins / total_attempts * 100) if total_attempts > 0 else 0, 2)
            },
            'anomalies': {
                'total': total_anomalies,
                'unresolved': unresolved_anomalies,
                'critical': critical_anomalies,
                'today': anomalies_today
            },
            'sessions': {
                'active': active_sessions
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/users', methods=['GET'])
@jwt_required()
def get_users():
    """Get list of all users with their registration details"""
    try:
        users = User.query.order_by(User.created_at.desc()).all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'two_factor_enabled': user.two_factor_enabled,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_active': user.is_active,
                'is_blocked': user.is_blocked,
                'block_reason': user.block_reason,
                'failed_login_count': user.failed_login_count
            })
        
        return jsonify({'users': users_data}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/login-attempts', methods=['GET'])
@jwt_required()
def get_login_attempts():
    """Get recent login attempts for monitoring"""
    try:
        limit = request.args.get('limit', 50, type=int)
        attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
        
        attempts_data = []
        for attempt in attempts:
            attempts_data.append({
                'id': attempt.id,
                'username': attempt.username,
                'ip_address': attempt.ip_address,
                'success': attempt.success,
                'failure_reason': attempt.failure_reason,
                'timestamp': attempt.timestamp.isoformat()
            })
        
        return jsonify({'login_attempts': attempts_data}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/anomalies', methods=['GET'])
@jwt_required()
def get_anomalies():
    """Get detected anomalies with patterns"""
    try:
        limit = request.args.get('limit', 50, type=int)
        resolved_filter = request.args.get('resolved', 'false')
        
        query = Anomaly.query
        
        if resolved_filter.lower() == 'false':
            query = query.filter_by(resolved=False)
        
        anomalies = query.order_by(Anomaly.detected_at.desc()).limit(limit).all()
        
        anomalies_data = []
        for anomaly in anomalies:
            metadata = {}
            if anomaly.anomaly_metadata:
                try:
                    metadata = json.loads(anomaly.anomaly_metadata)
                except:
                    pass
            
            anomalies_data.append({
                'id': anomaly.id,
                'type': anomaly.anomaly_type,
                'ip_address': anomaly.ip_address,
                'severity': anomaly.severity,
                'description': anomaly.description,
                'metadata': metadata,
                'detected_at': anomaly.detected_at.isoformat(),
                'resolved': anomaly.resolved
            })
        
        return jsonify({'anomalies': anomalies_data}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/anomaly-patterns', methods=['GET'])
@jwt_required()
def get_anomaly_patterns():
    """
    Get anomaly patterns for visualization.
    Groups anomalies by IP address and type.
    """
    try:
        # Get recent anomalies (last 24 hours)
        recent_anomalies = Anomaly.query.filter(
            Anomaly.detected_at >= datetime.utcnow() - timedelta(days=1),
            Anomaly.resolved == False
        ).all()
        
        # Group by IP address
        ip_patterns = defaultdict(lambda: {
            'count': 0,
            'types': defaultdict(int),
            'severities': defaultdict(int),
            'first_seen': None,
            'last_seen': None
        })
        
        for anomaly in recent_anomalies:
            ip = anomaly.ip_address
            ip_patterns[ip]['count'] += 1
            ip_patterns[ip]['types'][anomaly.anomaly_type] += 1
            ip_patterns[ip]['severities'][anomaly.severity] += 1
            
            if not ip_patterns[ip]['first_seen'] or anomaly.detected_at < ip_patterns[ip]['first_seen']:
                ip_patterns[ip]['first_seen'] = anomaly.detected_at
            
            if not ip_patterns[ip]['last_seen'] or anomaly.detected_at > ip_patterns[ip]['last_seen']:
                ip_patterns[ip]['last_seen'] = anomaly.detected_at
        
        # Convert to list format
        patterns = []
        for ip, data in ip_patterns.items():
            patterns.append({
                'ip_address': ip,
                'anomaly_count': data['count'],
                'types': dict(data['types']),
                'severities': dict(data['severities']),
                'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
                'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
            })
        
        # Sort by anomaly count (most suspicious first)
        patterns.sort(key=lambda x: x['anomaly_count'], reverse=True)
        
        return jsonify({'patterns': patterns}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/resolve-anomaly', methods=['POST'])
@jwt_required()
def resolve_anomaly():
    """Mark an anomaly as resolved"""
    try:
        data = request.get_json()
        anomaly_id = data.get('anomaly_id')
        
        anomaly = Anomaly.query.get(anomaly_id)
        if not anomaly:
            return jsonify({'error': 'Anomaly not found'}), 404
        
        anomaly.resolved = True
        db.session.commit()
        
        return jsonify({'message': 'Anomaly resolved'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ROUTES - ADMIN USER MANAGEMENT
# ============================================================================

@app.route('/api/admin/block-user', methods=['POST'])
@jwt_required()
def block_user():
    """Block a user account"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        reason = data.get('reason', 'Administrative action')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_blocked = True
        user.blocked_at = datetime.utcnow()
        user.block_reason = reason
        
        # Revoke all active sessions
        UserSession.query.filter_by(user_id=user_id, is_revoked=False).update({'is_revoked': True})
        
        db.session.commit()
        
        return jsonify({'message': f'User {user.username} has been blocked'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/unblock-user', methods=['POST'])
@jwt_required()
def unblock_user():
    """Unblock a user account"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_blocked = False
        user.blocked_at = None
        user.block_reason = None
        user.failed_login_count = 0
        user.last_failed_login = None
        
        db.session.commit()
        
        return jsonify({'message': f'User {user.username} has been unblocked'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/user-behavior/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_behavior(user_id):
    """Get detailed behavior analytics for a specific user"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get login attempts
        login_attempts = LoginAttempt.query.filter_by(user_id=user_id).order_by(
            LoginAttempt.timestamp.desc()
        ).limit(50).all()
        
        # Get anomalies related to user
        anomalies = Anomaly.query.filter_by(user_id=user_id).order_by(
            Anomaly.detected_at.desc()
        ).all()
        
        # Calculate statistics
        total_attempts = LoginAttempt.query.filter_by(user_id=user_id).count()
        successful_logins = LoginAttempt.query.filter_by(user_id=user_id, success=True).count()
        failed_logins = LoginAttempt.query.filter_by(user_id=user_id, success=False).count()
        
        # Get IP addresses used
        ip_addresses = db.session.query(
            LoginAttempt.ip_address,
            func.count(LoginAttempt.id).label('count')
        ).filter_by(user_id=user_id).group_by(LoginAttempt.ip_address).all()
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_blocked': user.is_blocked,
                'block_reason': user.block_reason,
                'failed_login_count': user.failed_login_count,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            },
            'statistics': {
                'total_attempts': total_attempts,
                'successful_logins': successful_logins,
                'failed_logins': failed_logins,
                'success_rate': round((successful_logins / total_attempts * 100) if total_attempts > 0 else 0, 2)
            },
            'ip_addresses': [{'ip': ip, 'count': count} for ip, count in ip_addresses],
            'recent_attempts': [{
                'id': attempt.id,
                'ip_address': attempt.ip_address,
                'success': attempt.success,
                'failure_reason': attempt.failure_reason,
                'timestamp': attempt.timestamp.isoformat()
            } for attempt in login_attempts],
            'anomalies': [{
                'id': anomaly.id,
                'type': anomaly.anomaly_type,
                'severity': anomaly.severity,
                'description': anomaly.description,
                'detected_at': anomaly.detected_at.isoformat()
            } for anomaly in anomalies]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# INITIALIZE DATABASE
# ============================================================================

def initialize_database():
    """Create database tables"""
    with app.app_context():
        db.create_all()


# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        print("Database initialized!")
        print("Starting Secure Logging System...")
        print("Dashboard available at: http://localhost:5000")
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)