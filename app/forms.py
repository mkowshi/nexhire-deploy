# --- app/forms.py ---
import re
from datetime import date
from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField, IntegerField, DateField, FileField)
from wtforms.validators import (DataRequired, Length, Email, EqualTo, ValidationError, Optional, NumberRange)
from flask_wtf.file import FileRequired, FileAllowed
from .models import User

def validate_password_complexity(form, field):
    password = field.data
    if len(password) < 8: raise ValidationError('Min 8 characters.')
    if not re.search("[a-z]", password): raise ValidationError('Needs lowercase.')
    if not re.search("[A-Z]", password): raise ValidationError('Needs uppercase.')
    if not re.search("[0-9]", password): raise ValidationError('Needs digit.')
    # FIX APPLIED HERE: Added 'r' for raw string to prevent SyntaxWarning
    if not re.search(r"[!@#$%^&*()-_=+\[\]{};:'\",.<>?/]", password): raise ValidationError('Needs special char.')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_complexity])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    role = SelectField('Register as', choices=[('job_seeker', 'Job Seeker'), ('employer', 'Employer')], validators=[DataRequired()])
    company_name = StringField('Company Name (if Employer)', validators=[Length(max=120)])
    submit = SubmitField('Register')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Username taken.')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first(): raise ValidationError('Email registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first() is None: raise ValidationError('No account with that email.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), validate_password_complexity])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')

class JobForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Job Description', validators=[DataRequired()])
    salary = StringField('Salary (Optional)', validators=[Optional(), Length(max=100)])
    location = StringField('Location', validators=[DataRequired(), Length(max=100)])
    category = StringField('Category (Optional)', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Post Job')

class ApplicationForm(FlaskForm):
    current_ctc = StringField('Current CTC', validators=[DataRequired(message="Current CTC is required."), Length(max=100)])
    expected_ctc = StringField('Expected CTC', validators=[DataRequired(message="Expected CTC is required."), Length(max=100)])
    notice_period_days = IntegerField('Notice Period (in days)', validators=[DataRequired(message="Notice period is required."), NumberRange(min=0)])
    earliest_join_date = DateField('Earliest Joining Date', format='%Y-%m-%d', validators=[DataRequired(message="Joining date is required.")])
    resume = FileField('Upload Resume (PDF, max 5MB)', validators=[FileRequired(message="Resume is required."), FileAllowed(['pdf'], 'PDFs only!')])
    submit = SubmitField('Submit Application')
    def validate_earliest_join_date(self, field):
        if field.data and field.data < date.today(): raise ValidationError("Joining date cannot be in the past.")

class RejectApplicationForm(FlaskForm):
    REJECTION_REASONS = [ ('', '-- Select a Reason --'), ('Not Qualified', 'Lacks required qualifications/experience'), ('Experience Mismatch', 'Experience level does not match role'), ('Position Filled', 'Position has already been filled'), ('Culture Fit', 'Concern about team/company culture fit'), ('Not Proceeding', 'Decided not to proceed (General)'), ('Other', 'Other (Specify in notes)') ]
    reason = SelectField('Rejection Reason', choices=REJECTION_REASONS, validators=[DataRequired(message="Please select a reason.")])
    notes = TextAreaField('Optional Notes', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Confirm Rejection')
    def validate_reason(self, field):
        if field.data == '': raise ValidationError("Please select a valid rejection reason.")

# --- End of forms.py ---