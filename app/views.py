# --- app/views.py ---
import os
import uuid
from threading import Thread
from functools import wraps
from datetime import datetime
import requests # <--- NEW IMPORT FOR BREVO API
from flask import (render_template, redirect, url_for, flash, request, Blueprint, current_app, abort, send_from_directory)
from flask_login import login_user, logout_user, login_required, current_user
# We no longer need flask_mail for the API method, but keeping it imported won't hurt if initialized in __init__.py
from flask_mail import Message 
from itsdangerous import SignatureExpired, BadSignature
from werkzeug.utils import secure_filename
from sqlalchemy.orm import joinedload
# --- V V V --- Cloudinary Import --- V V V ---
import cloudinary
import cloudinary.uploader
# --- ^ ^ ^ --- End Cloudinary Import --- ^ ^ ^ ---

from . import db, serializer
from .models import User, Job, Application
from .forms import (RegistrationForm, LoginForm, JobForm, RequestResetForm, ResetPasswordForm, ApplicationForm, RejectApplicationForm)

# --- Blueprints ---
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
jobs_bp = Blueprint('jobs', __name__)
employers_bp = Blueprint('employers', __name__)
admin_bp = Blueprint('admin', __name__)

# --- Decorators for Role Checks ---
def employer_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'employer':
            flash('This area is restricted to employers.', 'warning')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('This area is restricted to administrators.', 'warning')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def job_seeker_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'job_seeker':
            flash('You must be registered as a Job Seeker to perform this action.', 'warning')
            return redirect(request.referrer or url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


# --- ENTERPRISE FIX: Brevo API Email Functions ---
def send_async_email(app, subject, recipients, text_body, html_body):
    """Sends email via HTTP API (Port 443) to completely bypass Render's SMTP block."""
    with app.app_context():
        api_key = os.environ.get('EMAIL_API_KEY')
        sender_email = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@nexhire.com')
        
        if not api_key:
            app.logger.error("EMAIL_API_KEY is missing from environment variables!")
            return

        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json"
        }
        
        # Format the data for Brevo
        data = {
            "sender": {"email": sender_email, "name": "NexHire Team"},
            "to": [{"email": r} for r in recipients],
            "subject": subject,
            "htmlContent": html_body,
            "textContent": text_body
        }
        
        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code in [200, 201, 202]:
                app.logger.info(f"API email successfully sent to {recipients}")
            else:
                app.logger.error(f"API Email failed. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            app.logger.error(f"API Request crashed: {e}")

def send_email(subject, recipients, text_body, html_body):
    """Prepares the email and hands it off to a background API thread."""
    if not isinstance(recipients, list) or not recipients: 
        current_app.logger.error(f"Invalid recipients: {recipients}")
        return False
        
    app = current_app._get_current_object()
    
    # Pass the raw data to the thread instead of a Flask-Mail Message object
    Thread(target=send_async_email, args=(app, subject, recipients, text_body, html_body)).start()
    
    return True
# --- END ENTERPRISE FIX ---


# --- Main Routes ---
@main_bp.route('/')
def index():
    recent_jobs = Job.query.filter_by(is_approved=True).order_by(Job.posted_at.desc()).limit(5).all()
    return render_template('index.html', jobs=recent_jobs)

# --- Authentication Routes ---

# The Temporary Admin Creation Route (Phase 6 Workaround)
@auth_bp.route('/create_first_admin')
def create_first_admin():
    email = os.environ.get('DEFAULT_ADMIN_EMAIL')
    password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
    
    if not email or not password:
        return "Error: DEFAULT_ADMIN_EMAIL or DEFAULT_ADMIN_PASSWORD missing in Render Environment.", 400
        
    admin = User.query.filter_by(email=email).first()
    if not admin:
        new_admin = User(username='SuperAdmin', email=email, role='admin', is_verified=True)
        new_admin.set_password(password)
        try:
            db.session.add(new_admin)
            db.session.commit()
            return f"Admin {email} successfully created! You can now log in.", 200
        except Exception as e:
            db.session.rollback()
            return f"Database error: {e}", 500
            
    return "Admin already exists! Please try logging in.", 200

@auth_bp.route('/admin_cannot_post')
@login_required
@admin_required
def admin_cannot_post():
    flash('Administrators manage jobs via the Admin Dashboard, not the general "Post a Job" button.', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/admin_cannot_register')
@login_required
@admin_required
def admin_cannot_register():
    flash('Administrators cannot register new accounts. Use the Admin Dashboard for management.', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role=form.role.data, company_name=form.company_name.data if form.role.data == 'employer' else None, is_verified=False)
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
            current_app.logger.info(f"User registered: {user.username}, preparing API email.")
            token = serializer.dumps(user.email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
            verify_url = url_for('auth.verify_email', token=token, _external=True)
            
            # QA Trick: Still print to console just in case!
            current_app.logger.info(f"\n\n🚨 MOCK INBOX FOR {user.email} 🚨\nClick this link to verify: {verify_url}\n\n")

            subject = "Confirm Your NexHire Account"
            text_body = f"Please verify your account by clicking this link: {verify_url}"
            try:
                html_body = render_template('auth/email/verify_email.html', verify_url=verify_url)
            except Exception as template_error:
                current_app.logger.error(f"Error rendering verification email template: {template_error}")
                html_body = f"<p>Please verify your account by clicking <a href='{verify_url}'>this link</a>.</p>"

            try:
                send_email(subject, [user.email], text_body, html_body)
                flash('Registration successful! Check your email to verify.', 'success')
            except Exception as e:
                current_app.logger.error(f"API Trigger Exception: {e}")
                flash('Registered successfully, but the verification email failed to send.', 'warning')

            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Registration error. Please try again.', 'danger')
            current_app.logger.error(f"Reg error: {e}")
    return render_template('auth/register.html', title='Register', form=form)

@auth_bp.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash('Link expired.', 'warning')
        return redirect(url_for('auth.login'))
    except BadSignature:
        flash('Invalid link.', 'danger')
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('Already verified.', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Email verified!', 'success')
        current_app.logger.info(f"Email verified: {user.username}")
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Account not verified.', 'warning')
                return redirect(url_for('auth.login'))
            login_user(user, remember=form.remember_me.data)
            flash(f'Welcome {user.username}!', 'success')
            current_app.logger.info(f"Login: {user.username}")
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            elif user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'employer':
                return redirect(url_for('employers.dashboard'))
            else:
                return redirect(url_for('jobs.job_list'))
        else:
            flash('Invalid credentials.', 'danger')
            current_app.logger.warning(f"Failed login: {form.email.data}")
    return render_template('auth/login.html', title='Login', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    uname = current_user.username
    logout_user()
    flash('Logged out.', 'info')
    current_app.logger.info(f"Logout: {uname}")
    return redirect(url_for('main.index'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user:
            token = serializer.dumps(user.email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
            url = url_for('auth.reset_password', token=token, _external=True)
            subject = "NexHire Password Reset Request"
            text = f"Reset your password here: {url}"
            try:
                html = render_template('auth/email/reset_password_email.html', reset_url=url)
            except Exception as e:
                current_app.logger.error(f"Error rendering reset password template: {e}")
                html = f"<p>Reset your password <a href='{url}'>here</a>.</p>" 
            
            try:
                send_email(subject, [user.email], text, html)
            except Exception as e:
                current_app.logger.error(f"API Timeout Exception: {e}")

        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/forgot_password.html', title='Forgot Password', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash('Link expired.', 'warning')
        return redirect(url_for('auth.forgot_password'))
    except BadSignature:
        flash('Invalid link.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Password reset!', 'success')
        current_app.logger.info(f"Password reset: {user.username}")
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', title='Reset Password', form=form, token=token)

# --- Job Seeker Routes ---
@jobs_bp.route('/')
@jobs_bp.route('/list')
def job_list():
    page = request.args.get('page', 1, type=int)
    query = request.args.get('q', '')
    loc = request.args.get('location', '')
    cat = request.args.get('category', '')
    q = Job.query.filter_by(is_approved=True)
    if query: q = q.filter(db.or_(Job.title.ilike(f'%{query}%'), Job.description.ilike(f'%{query}%'), Job.company_name.ilike(f'%{query}%')))
    if loc: q = q.filter(Job.location.ilike(f'%{loc}%'))
    if cat: q = q.filter(Job.category.ilike(f'%{cat}%'))
    jobs = q.order_by(Job.posted_at.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template('jobs/index.html', title='Find Jobs', jobs=jobs, query=query, location=loc, category=cat)

@jobs_bp.route('/<int:job_id>')
def job_detail(job_id):
    job = Job.query.filter_by(id=job_id, is_approved=True).first_or_404()
    applied = False
    form = None
    if current_user.is_authenticated and current_user.role == 'job_seeker':
        if Application.query.filter_by(job_id=job.id, job_seeker_id=current_user.id).first():
            applied = True
        else:
            form = ApplicationForm()
    return render_template('jobs/detail.html', title=job.title, job=job, already_applied=applied, form=form)

@jobs_bp.route('/<int:job_id>/apply', methods=['GET', 'POST'])
@job_seeker_required
def apply_job(job_id):
    job = Job.query.filter_by(id=job_id, is_approved=True).first_or_404()
    if Application.query.filter_by(job_id=job.id, job_seeker_id=current_user.id).first():
        flash('Already applied.', 'info')
        return redirect(url_for('jobs.job_detail', job_id=job_id))

    form = ApplicationForm()
    if form.validate_on_submit():
        f = form.resume.data
        filename = secure_filename(f.filename)
        cloudinary_public_id = None

        if not filename:
            flash('Invalid resume filename provided.', 'danger')
            return render_template('jobs/detail.html', title=job.title, job=job, already_applied=False, form=form)

        # Cloudinary Upload
        try:
            cld_folder = f"job_portal/resumes/{job.id}"
            unique_id = uuid.uuid4().hex[:12]
            cld_public_id = f"{cld_folder}/{unique_id}_{filename}"

            current_app.logger.info(f"Attempting to upload resume to Cloudinary with public_id: {cld_public_id}")
            upload_result = cloudinary.uploader.upload(
                f, public_id=cld_public_id, folder=cld_folder, resource_type="raw"
            )

            if upload_result and upload_result.get('public_id'):
                cloudinary_public_id = upload_result.get('public_id')
                current_app.logger.info(f"Resume uploaded successfully to Cloudinary: {cloudinary_public_id}")
            else:
                raise Exception(f"Cloudinary upload failed. Result: {upload_result}")

        except Exception as e:
            current_app.logger.error(f"Cloudinary upload error for user {current_user.id}, job {job_id}: {e}")
            flash("Error uploading resume to cloud storage. Please try again.", 'danger')
            return render_template('jobs/detail.html', title=job.title, job=job, already_applied=False, form=form)

        # Create Application Record
        app_record = Application(
            job_id=job.id, job_seeker_id=current_user.id, current_ctc=form.current_ctc.data,
            expected_ctc=form.expected_ctc.data, notice_period_days=form.notice_period_days.data,
            earliest_join_date=form.earliest_join_date.data,
            resume_public_id=cloudinary_public_id,
            status='Submitted'
        )
        db.session.add(app_record)
        try:
            db.session.commit()
            flash('Application submitted!', 'success')
            current_app.logger.info(f"Application saved: user {current_user.id}, job {job_id}")
            now_time = datetime.utcnow()

            # Send Emails via Brevo API
            try:
                subj_seeker = f"Application Received: {job.title}"
                job_url = url_for('jobs.job_detail', job_id=job.id, _external=True)
                text_seeker = f"Hello {current_user.username},\n\nYour application for '{job.title}' at {job.company_name} was submitted.\nView job: {job_url}\n\nThanks,\nThe Job Portal Team"
                try:
                    html_seeker = render_template('jobs/email/application_confirmation.html', user=current_user, job=job, job_url=job_url, now=now_time)
                except Exception as e:
                    html_seeker = text_seeker.replace('\n', '<br>')
                
                send_email(subj_seeker, [current_user.email], text_seeker, html_seeker)
            except Exception as e:
                current_app.logger.error(f"Seeker confirm email API trigger error: {e}")

            try:
                emp = job.employer
                if emp and emp.email:
                    subj_emp = f"New Application: {job.title}"
                    apps_url = url_for('employers.view_applications', job_id=job.id, _external=True)
                    text_emp = f"New application for {job.title} from {current_user.username}.\nView: {apps_url}"
                    try:
                        html_emp = render_template('employers/email/new_application_notification.html', employer=emp, job=job, applicant=current_user, apps_url=apps_url, now=now_time)
                    except Exception as e:
                        html_emp = text_emp.replace('\n', '<br>')
                    
                    send_email(subj_emp, [emp.email], text_emp, html_emp)
            except Exception as e:
                current_app.logger.error(f"Employer notify email API trigger error: {e}")

            return redirect(url_for('jobs.job_detail', job_id=job_id))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"App DB save error: {e}")
            if cloudinary_public_id:
                try:
                    cloudinary.uploader.destroy(cloudinary_public_id, resource_type="raw")
                except Exception as del_e:
                    current_app.logger.error(f"Failed to delete orphaned Cloudinary file: {del_e}")
            flash(f'Database error submitting application.', 'danger')
            return render_template('jobs/detail.html', title=job.title, job=job, already_applied=False, form=form)

    elif request.method == 'POST':
        flash('Please correct errors below.', 'warning')
    return render_template('jobs/detail.html', title=job.title, job=job, already_applied=False, form=form)

@jobs_bp.route('/my-applications')
@login_required
@job_seeker_required
def my_applications():
    page = request.args.get('page', 1, type=int)
    applications_query = Application.query.options(joinedload(Application.job))\
                                        .filter_by(job_seeker_id=current_user.id)\
                                        .order_by(Application.applied_at.desc())
    applications = applications_query.paginate(page=page, per_page=15, error_out=False)
    return render_template('jobs/my_applications.html', title="My Applications", applications=applications)

# --- Employer Routes ---
@employers_bp.route('/dashboard')
@employer_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    jobs = Job.query.filter_by(employer_id=current_user.id).order_by(Job.posted_at.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template('employers/dashboard.html', title='Employer Dashboard', jobs=jobs)

@employers_bp.route('/jobs/new', methods=['GET', 'POST'])
@employer_required
def post_job():
    form = JobForm()
    if form.validate_on_submit():
        job = Job(title=form.title.data, description=form.description.data, salary=form.salary.data, location=form.location.data, category=form.category.data, company_name=current_user.company_name or "N/A", employer_id=current_user.id, is_approved=False)
        db.session.add(job)
        try:
            db.session.commit()
            flash('Job posted pending approval.', 'success')
            current_app.logger.info(f"Job posted: {job.id} by {current_user.id}")
            
            # Notify Admins via API
            try:
                admins = User.query.filter_by(role='admin').all()
                emails = [a.email for a in admins if a.email]
                if emails:
                    subj = "NexHire: New Job Approval Required"
                    url = url_for('admin.manage_jobs', status='pending', _external=True)
                    text = f"New job '{job.title}' needs approval.\nReview here: {url}"
                    try:
                        html = render_template('admin/email/new_job_notification.html', job=job, user=current_user, admin_jobs_url=url)
                    except:
                        html = text.replace('\n', '<br>')
                    send_email(subj, emails, text, html)
            except Exception as e:
                current_app.logger.error(f"Admin notify email API trigger error: {e}")
                
            return redirect(url_for('employers.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error posting job: {e}', 'danger')
            current_app.logger.error(f"Job post error: {e}")
    return render_template('employers/new_job.html', title='Post New Job', form=form)

@employers_bp.route('/jobs/<int:job_id>/edit', methods=['GET', 'POST'])
@employer_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id:
        abort(403)
    form = JobForm(obj=job)
    if form.validate_on_submit():
        form.populate_obj(job)
        job.is_approved = False
        try:
            db.session.commit()
            flash('Job updated pending re-approval.', 'success')
            current_app.logger.info(f"Job edited: {job_id} by {current_user.id}")
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating job: {e}.', 'danger')
            current_app.logger.error(f"Job update error: {e}")
        return redirect(url_for('employers.dashboard'))
    return render_template('employers/edit_job.html', title='Edit Job', form=form, job=job)

@employers_bp.route('/jobs/<int:job_id>/delete', methods=['POST'])
@employer_required
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id: abort(403)
    try:
        db.session.delete(job)
        db.session.commit()
        flash('Job deleted.', 'success')
        current_app.logger.info(f"Job deleted: {job_id} by {current_user.id}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting job: {e}.', 'danger')
        current_app.logger.error(f"Job delete error: {e}")
    return redirect(url_for('employers.dashboard'))

@employers_bp.route('/jobs/<int:job_id>/applications')
@employer_required
def view_applications(job_id):
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id: abort(403)
    page = request.args.get('page', 1, type=int)
    apps_query = Application.query.filter_by(job_id=job_id).order_by(Application.status.asc(), Application.applied_at.desc())
    applications = apps_query.paginate(page=page, per_page=15, error_out=False)
    reject_form = RejectApplicationForm()
    return render_template('employers/applications.html', title=f'Applications for {job.title}', job=job, applications=applications, reject_form=reject_form)

@employers_bp.route('/applications/<int:application_id>/reject', methods=['POST'])
@employer_required
def reject_application(application_id):
    application = Application.query.get_or_404(application_id)
    job = application.job
    if job.employer_id != current_user.id:
        flash("Permission denied.", "danger")
        current_app.logger.warning(f"Unauthorized reject attempt: user {current_user.id}, app {application_id}")
        abort(403)
    if application.status not in ['Submitted', 'Viewed', 'Shortlisted', 'Interviewing']:
        flash(f"Cannot reject. Status is '{application.status}'.", "warning")
        return redirect(url_for('employers.view_applications', job_id=job.id))

    form = RejectApplicationForm()
    if form.validate_on_submit():
        application.status = 'Rejected'
        application.status_updated_at = datetime.utcnow()
        selected_reason_text = dict(form.reason.choices).get(form.reason.data, "No specific reason provided")
        application.rejection_reason = f"{selected_reason_text}"
        if form.notes.data:
            application.rejection_reason += f" | Notes: {form.notes.data}"
        try:
            db.session.commit()
            flash(f"Application from {application.job_seeker.username} rejected.", "success")
            
            # API Rejection Email
            try:
                applicant = application.job_seeker
                if applicant and applicant.email:
                    subject = f"Update on application for {job.title}"
                    text = f"Update on {job.title}:\nReason: {selected_reason_text}\nNotes: {form.notes.data or 'N/A'}"
                    try:
                        html = render_template('jobs/email/application_rejection.html', applicant=applicant, job=job, reason=selected_reason_text, notes=form.notes.data)
                    except:
                        html = text.replace('\n', '<br>')
                    send_email(subject, [applicant.email], text, html)
            except Exception as e:
                current_app.logger.error(f"Rejection email API trigger error: {e}")
                
        except Exception as e:
            db.session.rollback()
            flash("DB error updating application.", "danger")
            current_app.logger.error(f"DB error rejecting app {application_id}: {e}")
    else:
        validation_errors = form.errors
        flash("Could not reject application. Please select a valid reason.", "danger")
    return redirect(url_for('employers.view_applications', job_id=job.id))

@employers_bp.route('/applications/<int:application_id>/update_status', methods=['POST'])
@employer_required
def update_application_status(application_id):
    application = Application.query.get_or_404(application_id)
    job = application.job

    if job.employer_id != current_user.id:
        flash("Permission denied.", "danger")
        abort(403)

    new_status = request.form.get('new_status')
    ALLOWED_UPDATE_STATUSES = ['Viewed', 'Shortlisted', 'Interviewing', 'Offer Made', 'Hired', 'Offer Declined']
    TERMINAL_STATUSES = ['Rejected', 'Hired', 'Offer Declined']

    if not new_status or new_status not in ALLOWED_UPDATE_STATUSES:
        flash(f"Invalid status '{new_status}' requested.", "danger")
        return redirect(url_for('employers.view_applications', job_id=job.id))

    if application.status in TERMINAL_STATUSES:
        flash(f"Cannot update status. Application is already '{application.status}'.", "warning")
        return redirect(url_for('employers.view_applications', job_id=job.id))

    application.status = new_status
    application.status_updated_at = datetime.utcnow()
    if application.status != 'Rejected':
         application.rejection_reason = None

    try:
        db.session.commit()
        flash(f"Application status updated to '{new_status}'.", "success")

        if new_status == 'Offer Made':
            try:
                applicant = application.job_seeker
                if applicant and applicant.email:
                    subject = f"Congratulations! Offer for {job.title}"
                    text_body = f"Hello {applicant.username},\n\nWe are pleased to extend an offer for '{job.title}'. Details to follow.\n\nRegards"
                    try:
                        html_body = render_template('jobs/email/offer_notification.html', applicant=applicant, job=job)
                    except:
                        html_body = text_body.replace('\n', '<br>')
                    send_email(subject, [applicant.email], text_body, html_body)
            except Exception as e:
                current_app.logger.error(f"Offer email API trigger error: {e}")

    except Exception as e:
        db.session.rollback()
        flash("Database error updating application status.", "danger")

    return redirect(url_for('employers.view_applications', job_id=job.id))

# --- Admin Routes ---
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    pending = Job.query.filter_by(is_approved=False).count()
    total_users = User.query.count()
    total_jobs = Job.query.count()
    return render_template('admin/index.html', title='Admin Dashboard', pending_jobs_count=pending, total_users_count=total_users, total_jobs_count=total_jobs)

@admin_bp.route('/users')
@admin_required
def manage_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('admin/manage_users.html', title='Manage Users', users=users)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        if 'toggle_verify' in request.form:
            user.is_verified = not user.is_verified
            db.session.commit()
            flash(f"User '{user.username}' verification updated.", "success")
            return redirect(url_for('admin.manage_users'))
        flash('No update action performed.', 'info')
    return render_template('admin/edit_user.html', title=f'Edit User {user.username}', user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('Cannot delete yourself.', 'danger')
        return redirect(url_for('admin.manage_users'))
    if user_to_delete.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
         flash('Cannot delete last admin.', 'danger')
         return redirect(url_for('admin.manage_users'))
    username = user_to_delete.username
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User {username} deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {e}', 'danger')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/jobs')
@admin_required
def manage_jobs():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')
    query = Job.query
    if status == 'pending':
        query = query.filter_by(is_approved=False)
    elif status == 'approved':
        query = query.filter_by(is_approved=True)
    jobs = query.order_by(Job.is_approved.asc(), Job.posted_at.desc()).paginate(page=page, per_page=15, error_out=False)
    total = Job.query.count()
    pending = Job.query.filter_by(is_approved=False).count()
    approved = Job.query.filter_by(is_approved=True).count()
    return render_template(
        'admin/manage_jobs.html', title='Manage Jobs', jobs=jobs, filter_status=status,
        total_jobs_count=total, pending_jobs_count=pending, approved_jobs_count=approved
    )

@admin_bp.route('/jobs/<int:job_id>/approve', methods=['POST'])
@admin_required
def approve_job(job_id):
    job = Job.query.get_or_404(job_id)
    if not job.is_approved:
        job.is_approved = True
        db.session.commit()
        flash(f'Job approved.', 'success')
        
        # API Job Approval Email
        try:
            employer = job.employer
            if employer and employer.email:
                subject = f"Your Job Posting Approved: {job.title}"
                job_url = url_for('jobs.job_detail', job_id=job.id, _external=True)
                dashboard_url = url_for('employers.dashboard', _external=True)
                text_body = f"Hello {employer.username},\n\nYour job '{job.title}' has been approved.\nView job: {job_url}"
                try:
                    html_body = render_template('employers/email/job_approved_notification.html', employer=employer, job=job, job_url=job_url, dashboard_url=dashboard_url)
                except:
                    html_body = text_body.replace('\n', '<br>')
                send_email(subject, [employer.email], text_body, html_body)
        except Exception as e:
            current_app.logger.error(f"Job approval email API trigger error: {e}")
    else:
        flash(f'Job already approved.', 'info')
    return redirect(url_for('admin.manage_jobs', status=request.args.get('status', 'pending')))

@admin_bp.route('/jobs/<int:job_id>/unapprove', methods=['POST'])
@admin_required
def unapprove_job(job_id):
    job = Job.query.get_or_404(job_id)
    if job.is_approved:
        job.is_approved = False
        db.session.commit()
        flash(f'Job unapproved.', 'success')
    else:
        flash(f'Job already not approved.', 'info')
    return redirect(url_for('admin.manage_jobs', status=request.args.get('status', 'approved')))

@admin_bp.route('/jobs/<int:job_id>/admin_delete', methods=['POST'])
@admin_required
def admin_delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    title = job.title
    try:
        db.session.delete(job)
        db.session.commit()
        flash(f'Job "{title}" deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting job: {e}', 'danger')
    return redirect(url_for('admin.manage_jobs', status=request.args.get('status', 'all')))

@admin_bp.route('/jobs/<int:job_id>/admin_edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_job(job_id):
    job = Job.query.get_or_404(job_id)
    form = JobForm(obj=job)
    if form.validate_on_submit():
        form.populate_obj(job)
        try:
            db.session.commit()
            flash(f'Job updated by admin.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating job: {e}', 'danger')
        return redirect(url_for('admin.manage_jobs'))
    flash("Admin job edit page not fully implemented.", "info")
    return redirect(url_for('admin.manage_jobs'))

# --- End of views.py ---