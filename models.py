from datetime import datetime, date

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash

# Single SQLAlchemy object used across the app
db = SQLAlchemy()


class AdminUser(db.Model):
    """Admin is pre-created, no self-registration."""
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class StudentUser(db.Model):
    """Student account with basic details."""
    __tablename__ = "student_users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(120))
    cgpa = db.Column(db.Float)

    password_hash = db.Column(db.String(200), nullable=False)

    # active / blacklisted
    account_status = db.Column(db.String(20), default="active")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    profile = db.relationship(
        "StudentProfile",
        back_populates="student",
        uselist=False,
        cascade="all, delete-orphan",
    )

    applications = db.relationship(
        "Application",
        back_populates="student",
        cascade="all, delete-orphan",
    )


class StudentProfile(db.Model):
    """Separate profile + resume table."""
    __tablename__ = "student_profiles"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(
        db.Integer, db.ForeignKey("student_users.id"), nullable=False, unique=True
    )

    resume_filename = db.Column(db.String(200))
    skills = db.Column(db.String(250))
    about_me = db.Column(db.Text)
    linkedin_url = db.Column(db.String(200))

    student = db.relationship("StudentUser", back_populates="profile")


class CompanyAccount(db.Model):
    """Company account table."""
    __tablename__ = "company_accounts"

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(150), nullable=False)
    contact_person = db.Column(db.String(120))
    contact_email = db.Column(db.String(120), unique=True, nullable=False)
    contact_phone = db.Column(db.String(20))
    website_url = db.Column(db.String(200))
    description = db.Column(db.Text)
    password_hash = db.Column(db.String(200), nullable=False)

    # pending / approved / rejected
    approval_state = db.Column(db.String(20), default="pending")

    # active / blacklisted
    account_state = db.Column(db.String(20), default="active")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    drives = db.relationship(
        "PlacementDrive",
        back_populates="company",
        cascade="all, delete-orphan",
    )


class PlacementDrive(db.Model):
    """Placement drive created by a company."""
    __tablename__ = "placement_drives"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer, db.ForeignKey("company_accounts.id"), nullable=False
    )

    drive_title = db.Column(db.String(150), nullable=False)
    job_role = db.Column(db.String(150), nullable=False)
    job_location = db.Column(db.String(120))
    salary_package = db.Column(db.String(80))
    job_description = db.Column(db.Text, nullable=False)
    eligibility_criteria = db.Column(db.String(250))

    application_deadline = db.Column(db.Date, nullable=False)

    # pending / approved / closed
    drive_status = db.Column(db.String(20), default="pending")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    company = db.relationship("CompanyAccount", back_populates="drives")
    applications = db.relationship(
        "Application",
        back_populates="drive",
        cascade="all, delete-orphan",
    )


class Application(db.Model):
    """Student application for a specific drive."""
    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(
        db.Integer, db.ForeignKey("student_users.id"), nullable=False
    )
    drive_id = db.Column(
        db.Integer, db.ForeignKey("placement_drives.id"), nullable=False
    )

    applied_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    # Applied / Shortlisted / Interview / Selected / Rejected / Placed
    current_status = db.Column(db.String(20), default="Applied")

    recruiter_remark = db.Column(db.String(250))

    # extra feature: student can store a note about the application
    student_note = db.Column(db.String(250))

    student = db.relationship("StudentUser", back_populates="applications")
    drive = db.relationship("PlacementDrive", back_populates="applications")

    # prevent duplicate applications per student per drive
    __table_args__ = (
        UniqueConstraint("student_id", "drive_id", name="uq_student_drive"),
    )


def bootstrap_admin():
    """
    Programmatically create a default admin user if not present.

    Username: admin
    Password: admin123
    """
    existing = AdminUser.query.filter_by(username="admin").first()
    if existing:
        return

    admin = AdminUser(
        username="admin",
        password_hash=generate_password_hash("admin123"),
    )
    db.session.add(admin)
    db.session.commit()