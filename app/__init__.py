# --- app/__init__.py ---

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate  # <--- CRITICAL IMPORT
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import cloudinary
import cloudinary.utils
from werkzeug.security import generate_password_hash

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()  # <--- CRITICAL INITIALIZATION
login_manager = LoginManager()
mail = Mail()
serializer = None

# Configure logging formatter
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

def create_app(config_class=None):
    app = Flask(__name__, instance_relative_config=True)

    # Default Upload Folder Path
    default_upload_folder = os.path.join(app.instance_path, 'uploads', 'resumes')

    # Load Configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'change_this_dev_secret_key'),
        SECURITY_PASSWORD_SALT=os.environ.get('SECURITY_PASSWORD_SALT', 'change_this_dev_salt'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(app.instance_path, 'site.db')}"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', default_upload_folder),
        MAX_CONTENT_LENGTH = 5 * 1024 * 1024,
        MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.example.com'),
        MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
        MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't'],
        MAIL_USE_SSL=os.environ.get('MAIL_USE_SSL', 'False').lower() in ['true', '1', 't'],
        MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
        MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
        MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com'),
        # --- FIX APPLIED HERE: 5 Second Mail Timeout ---
        MAIL_TIMEOUT=5,
    )

    # Ensure Instance Folder Exists
    try: os.makedirs(app.instance_path, exist_ok=True)
    except OSError as e: app.logger.error(f"Error creating instance dir {app.instance_path}: {e}")

    # Configure Cloudinary SDK
    try:
        cloudinary.config(
            cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'), 
            api_key = os.environ.get('CLOUDINARY_API_KEY'), 
            api_secret = os.environ.get('CLOUDINARY_API_SECRET'), 
            secure=True
        )
    except Exception as e: app.logger.error(f"Cloudinary config error: {e}")

    # Initialize Flask Extensions
    try: 
        db.init_app(app)
        migrate.init_app(app, db)  # <--- CRITICAL CONNECTION
        login_manager.init_app(app)
        mail.init_app(app)
    except Exception as e: app.logger.error(f"Error initializing Flask extensions: {e}")

    # Initialize Serializer
    global serializer; serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # Configure Flask-Login
    login_manager.login_view = 'auth.login'; login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        try: return User.query.get(int(user_id))
        except: return None

    # Context Processors
    @app.context_processor
    def inject_now(): return {'now': datetime.utcnow}
    
    @app.context_processor
    def utility_processor():
        def get_cloudinary_raw_url(public_id):
            if not public_id: return None
            try:
                if cloudinary.config().cloud_name: 
                    url_tuple = cloudinary.utils.cloudinary_url(public_id, resource_type="raw", secure=True)
                    return url_tuple[0] if url_tuple else None
                return None
            except: return None
        return dict(get_cloudinary_raw_url=get_cloudinary_raw_url)

    # Register Blueprints
    try:
        from .views import main_bp, auth_bp, jobs_bp, employers_bp, admin_bp
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(jobs_bp, url_prefix='/jobs')
        app.register_blueprint(employers_bp, url_prefix='/employer')
        app.register_blueprint(admin_bp, url_prefix='/admin')
    except Exception as e: app.logger.error(f"Error registering blueprints: {e}")

    # Setup Logging
    log_dir = 'logs'
    log_file_path = os.path.join(log_dir, 'job_portal.log')
    if not app.debug and not app.testing:
        if not os.path.exists(log_dir): os.mkdir(log_dir)
        file_handler = RotatingFileHandler(log_file_path, maxBytes=10240, backupCount=10)
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    # Create Database Tables & Default Admin
    with app.app_context():
        try:
            db.create_all()
            from .models import User
            if not User.query.filter_by(role='admin').first():
                app.logger.info("No admin found. Creating default admin...")
                default_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@nexhire.local')
                default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'AdminPass123!')
                
                if not User.query.filter_by(email=default_email).first():
                    admin_user = User(
                        username='admin',
                        email=default_email,
                        role='admin',
                        is_verified=True
                    )
                    admin_user.set_password(default_password)
                    db.session.add(admin_user)
                    db.session.commit()
                    app.logger.info(f"Default admin '{default_email}' created.")
        except Exception as e:
            app.logger.error(f"DB Setup Error: {e}")

    return app