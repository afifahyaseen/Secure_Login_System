from app import app, db, User
from werkzeug.security import generate_password_hash

def setup_database():
    """Initialize database and create tables"""
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("✓ Database tables created successfully!")

        # Ensure new columns exist for blocking (safe no-op if already present)
        # This avoids "no such column: users.is_blocked" when upgrading.
        migration_statements = [
            "ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT 0",
            "ALTER TABLE users ADD COLUMN blocked_at DATETIME",
            "ALTER TABLE users ADD COLUMN block_reason VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN last_failed_login DATETIME",
            "ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'"
        ]

        for stmt in migration_statements:
            try:
                db.session.execute(stmt)
                db.session.commit()
            except:
                db.session.rollback()
        
        # Check if admin user already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("\nCreating default admin user...")
            admin = User(
                username='admin',
                email='admin@securelogging.local',
                password_hash=generate_password_hash('admin123'),  # Change this in production!
                two_factor_enabled=False,
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("✓ Default admin user created!")
            print("  Username: admin")
            print("  Password: admin123")
            print("  ⚠️  WARNING: Change this password immediately in production!")
        else:
            print("\n✓ Admin user already exists")
        
        print("\n" + "="*50)
        print("Setup complete! You can now run: python app.py")
        print("="*50)

if __name__ == '__main__':
    setup_database()