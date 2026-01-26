from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import Date, Text, DateTime
from . import db  # Import the db instance from your app factory

class User(UserMixin, db.Model):
    """User model for authentication and role-based access control."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='job_seeker')  # 'job_seeker', 'employer', 'admin'
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    company_name = db.Column(db.String(120), nullable=True)  # Specific to employers
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # RELATIONSHIPS WITH CASCADE DELETE
    # cascade="all, delete-orphan" ensures that if a User is deleted, 
    # all their posted jobs or applications are also removed automatically.
    jobs_posted = db.relationship(
        'Job', 
        backref='employer', 
        lazy='dynamic', 
        foreign_keys='Job.employer_id',
        cascade="all, delete-orphan"
    )
    
    applications_submitted = db.relationship(
        'Application', 
        backref='job_seeker', 
        lazy='dynamic', 
        foreign_keys='Application.job_seeker_id',
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    # Flask-Login required methods
    def get_id(self):
        """Returns the user ID as a string for Flask-Login."""
        return str(self.id)

    @property
    def is_active(self):
        """Checks if the user account is active (verified). Used by Flask-Login."""
        return self.is_verified

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Job(db.Model):
    """Job listing model representing a recruitment post."""
    __tablename__ = 'jobs'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    salary = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=True, index=True)
    company_name = db.Column(db.String(120), nullable=False)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

    # Foreign Key to the employer
    employer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Cascade applications if a job is removed
    applications = db.relationship(
        'Application', 
        backref='job', 
        lazy='dynamic', 
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Job {self.title} by {self.company_name}>"


class Application(db.Model):
    """Model representing a seeker's submission for a job."""
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key=True)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Seeker Details
    current_ctc = db.Column(db.String(100), nullable=True)
    expected_ctc = db.Column(db.String(100), nullable=True)
    notice_period_days = db.Column(db.Integer, nullable=True)
    earliest_join_date = db.Column(db.Date, nullable=True)

    # Cloudinary Integration
    resume_public_id = db.Column(db.String(255), nullable=True)

    # Workflow Status
    status = db.Column(db.String(30), default='Submitted', nullable=False, index=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    status_updated_at = db.Column(db.DateTime, nullable=True)

    # Foreign Keys
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    job_seeker_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Ensure a user only applies once per job
    __table_args__ = (db.UniqueConstraint('job_id', 'job_seeker_id', name='_job_seeker_uc'),)

    def __repr__(self):
        return f"<Application ID {self.id} Status {self.status}>"