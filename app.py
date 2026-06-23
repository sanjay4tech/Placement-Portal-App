import os
from datetime import datetime, date

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_from_directory,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

from models import (
    db,
    AdminUser,
    StudentUser,
    StudentProfile,
    CompanyAccount,
    PlacementDrive,
    Application,
    bootstrap_admin,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "simple-student-secret-key"

# Database will be created inside the main directory
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///portal.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Resumes Upload Path
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()
    bootstrap_admin()

# -----------------------------------------------------------------------------
# INDEX ROUTE
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    role = session.get("active_role")
    if role == "admin":
        return redirect(url_for("admin_home"))
    if role == "company":
        return redirect(url_for("company_home"))
    if role == "student":
        return redirect(url_for("student_home"))
    return redirect(url_for("sign_in"))


# -----------------------------------------------------------------------------
# AUTHENTICATION Helper Routes
# -----------------------------------------------------------------------------
def _clear_login_state():
    session.pop("user_id", None)
    session.pop("active_role", None)

@app.route("/auth/signin", methods=["GET", "POST"])
def sign_in():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        # Admin login
        admin = AdminUser.query.filter_by(username=identifier).first()
        if admin and admin.is_active and check_password_hash(admin.password_hash, password):
            _clear_login_state()
            session["user_id"] = admin.id
            session["active_role"] = "admin"
            flash("Logged in as Admin.", "success")
            return redirect(url_for("admin_home"))

        # Student login
        student = StudentUser.query.filter_by(email=identifier).first()
        if student and check_password_hash(student.password_hash, password):
            if student.account_status == "blacklisted":
                flash("Your student account is blacklisted.", "danger")
            else:
                _clear_login_state()
                session["user_id"] = student.id
                session["active_role"] = "student"
                flash("Logged in as Student.", "success")
                return redirect(url_for("student_home"))

        # Company login
        company = CompanyAccount.query.filter_by(contact_email=identifier).first()
        if company and check_password_hash(company.password_hash, password):
            if company.approval_state != "approved":
                flash("Company is not approved yet.", "warning")
            elif company.account_state == "blacklisted":
                flash("Company account is blacklisted.", "danger")
            else:
                _clear_login_state()
                session["user_id"] = company.id
                session["active_role"] = "company"
                flash("Logged in as Company.", "success")
                return redirect(url_for("company_home"))

        flash("Invalid login details.", "danger")
    return render_template("login.html")

@app.route("/auth/signout")
def sign_out():
    _clear_login_state()
    flash("Logged out.", "info")
    return redirect(url_for("sign_in"))

@app.route("/auth/register/student", methods=["GET", "POST"])
def register_student():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        cgpa_str = request.form.get("cgpa", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not full_name or not email or not phone or not password:
            flash("Name, email, phone and password are required.", "warning")
            return redirect(url_for("register_student"))

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("register_student"))

        if StudentUser.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("register_student"))

        if StudentUser.query.filter_by(phone_number=phone).first():
            flash("Phone already registered.", "warning")
            return redirect(url_for("register_student"))

        try:
            cgpa_value = float(cgpa_str) if cgpa_str else None
        except ValueError:
            cgpa_value = None

        student = StudentUser(
            full_name=full_name,
            email=email,
            phone_number=phone,
            department=department,
            cgpa=cgpa_value,
            password_hash=generate_password_hash(password),
        )
        db.session.add(student)
        db.session.flush()

        profile = StudentProfile(student_id=student.id)
        try:
            db.session.add(profile)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Database error: Registration failed.", "danger")
            return redirect(url_for("register_student"))

        flash("Student registered successfully. Please login.", "success")
        return redirect(url_for("sign_in"))
    return render_template("register_student.html")

@app.route("/auth/register/company", methods=["GET", "POST"])
def register_company():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        contact_person = request.form.get("contact_person", "").strip()
        contact_email = request.form.get("contact_email", "").strip().lower()
        contact_phone = request.form.get("contact_phone", "").strip()
        website_url = request.form.get("website_url", "").strip()
        description = request.form.get("description", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not company_name or not contact_email or not password:
            flash("Company name, email and password are required.", "warning")
            return redirect(url_for("register_company"))

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("register_company"))

        if CompanyAccount.query.filter_by(contact_email=contact_email).first():
            flash("This email is already registered.", "warning")
            return redirect(url_for("register_company"))

        company = CompanyAccount(
            company_name=company_name,
            contact_person=contact_person,
            contact_email=contact_email,
            contact_phone=contact_phone,
            website_url=website_url,
            description=description,
            password_hash=generate_password_hash(password),
            approval_state="pending",
            account_state="active",
        )
        try:
            db.session.add(company)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Database error: Account credentials may already exist.", "danger")
            return redirect(url_for("register_company"))

        flash("Company registered. Wait for admin approval.", "success")
        return redirect(url_for("sign_in"))
    return render_template("register_company.html")


# -----------------------------------------------------------------------------
# ADMIN ROUTES
# -----------------------------------------------------------------------------
def is_admin():
    if session.get("active_role") != "admin":
        return False
    admin_id = session.get("user_id")
    admin = AdminUser.query.get(admin_id)
    if not admin or not admin.is_active:
        return False
    return True

@app.route("/admin/home")
def admin_home():
    if not is_admin(): return redirect(url_for("sign_in"))
    
    total_students = StudentUser.query.count()
    total_companies = CompanyAccount.query.count()
    total_drives = PlacementDrive.query.count()
    total_applications = Application.query.count()
    pending_companies = CompanyAccount.query.filter_by(approval_state="pending").all()
    pending_drives = PlacementDrive.query.filter_by(drive_status="pending").all()
    
    return render_template("admin_dashboard.html",
                           total_students=total_students, total_companies=total_companies,
                           total_drives=total_drives, total_applications=total_applications,
                           pending_companies=pending_companies, pending_drives=pending_drives)

@app.route("/admin/companies")
def manage_companies():
    if not is_admin(): return redirect(url_for("sign_in"))
    
    search = request.args.get("q", "").strip()
    query = CompanyAccount.query
    if search:
        like = f"%{search}%"
        filters = [CompanyAccount.company_name.ilike(like), CompanyAccount.contact_email.ilike(like)]
        if search.isdigit(): filters.append(CompanyAccount.id == int(search))
        query = query.filter(db.or_(*filters))
        
    companies = query.order_by(CompanyAccount.created_at.desc()).all()
    return render_template("admin_companies.html", companies=companies)

@app.route("/admin/companies/<int:company_id>/set_state", methods=["POST"])
def update_company_state(company_id):
    if not is_admin(): return redirect(url_for("sign_in"))
    
    company = CompanyAccount.query.get_or_404(company_id)
    new_approval = request.form.get("approval_state")
    new_account_state = request.form.get("account_state")
    
    if new_approval in {"pending", "approved", "rejected"}:
        company.approval_state = new_approval
    if new_account_state in {"active", "blacklisted"}:
        company.account_state = new_account_state
        
    db.session.commit()
    flash("Company status updated.", "success")
    return redirect(url_for("manage_companies"))

@app.route("/admin/students")
def manage_students():
    if not is_admin(): return redirect(url_for("sign_in"))
    
    search = request.args.get("q", "").strip()
    query = StudentUser.query
    if search:
        like = f"%{search}%"
        filters = [StudentUser.full_name.ilike(like), StudentUser.email.ilike(like), StudentUser.phone_number.ilike(like)]
        if search.isdigit(): filters.append(StudentUser.id == int(search))
        query = query.filter(db.or_(*filters))
        
    students = query.order_by(StudentUser.created_at.desc()).all()
    return render_template("admin_students.html", students=students)

@app.route("/admin/students/<int:student_id>/set_state", methods=["POST"])
def update_student_state(student_id):
    if not is_admin(): return redirect(url_for("sign_in"))
    
    student = StudentUser.query.get_or_404(student_id)
    new_state = request.form.get("account_status")
    if new_state in {"active", "blacklisted"}:
        student.account_status = new_state
        
    db.session.commit()
    flash("Student status updated.", "success")
    return redirect(url_for("manage_students"))

@app.route("/admin/drives")
def manage_drives():
    if not is_admin(): return redirect(url_for("sign_in"))
    
    drives = PlacementDrive.query.join(CompanyAccount).add_entity(CompanyAccount).order_by(PlacementDrive.created_at.desc()).all()
    return render_template("admin_drives.html", drives=drives)

@app.route("/admin/drives/<int:drive_id>/set_state", methods=["POST"])
def update_drive_state(drive_id):
    if not is_admin(): return redirect(url_for("sign_in"))
    
    drive = PlacementDrive.query.get_or_404(drive_id)
    new_status = request.form.get("drive_status")
    if new_status in {"pending", "approved", "closed"}:
        drive.drive_status = new_status
        db.session.commit()
        flash("Drive status updated.", "success")
    else:
        flash("Invalid status value.", "warning")
        
    return redirect(url_for("manage_drives"))

@app.route("/admin/applications")
def view_applications():
    if not is_admin(): return redirect(url_for("sign_in"))
    
    applications = Application.query.join(StudentUser).join(PlacementDrive).join(CompanyAccount).add_entity(StudentUser).add_entity(PlacementDrive).add_entity(CompanyAccount).order_by(Application.applied_on.desc()).all()
    return render_template("admin_applications.html", applications=applications)


# -----------------------------------------------------------------------------
# COMPANY ROUTES
# -----------------------------------------------------------------------------
def company_check():
    if session.get("active_role") != "company":
        return None
    company_id = session.get("user_id")
    company = CompanyAccount.query.get(company_id)
    if not company or company.approval_state != "approved" or company.account_state == "blacklisted":
        return None
    return company

@app.route("/company/home")
def company_home():
    company = company_check()
    if not company: return redirect(url_for("sign_in"))
    
    drives = PlacementDrive.query.filter_by(company_id=company.id).order_by(PlacementDrive.created_at.desc()).all()
    app_counts = {d.id: len(d.applications) for d in drives}
    return render_template("company_dashboard.html", company=company, drives=drives, application_counts=app_counts)

@app.route("/company/drives/new", methods=["GET", "POST"])
def create_drive():
    company = company_check()
    if not company: return redirect(url_for("sign_in"))
    
    if request.method == "POST":
        drive_title = request.form.get("drive_title", "").strip()
        job_role = request.form.get("job_role", "").strip()
        job_location = request.form.get("job_location", "").strip()
        salary_package = request.form.get("salary_package", "").strip()
        job_description = request.form.get("job_description", "").strip()
        eligibility_criteria = request.form.get("eligibility_criteria", "").strip()
        deadline_str = request.form.get("application_deadline", "").strip()

        if not drive_title or not job_role or not job_description or not deadline_str:
            flash("Title, role, description and deadline are required.", "warning")
            return redirect(url_for("create_drive"))

        try:
            deadline_date = datetime.strptime(deadline_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Deadline must be in YYYY-MM-DD format.", "warning")
            return redirect(url_for("create_drive"))

        drive = PlacementDrive(company_id=company.id, drive_title=drive_title, job_role=job_role,
                               job_location=job_location, salary_package=salary_package, job_description=job_description,
                               eligibility_criteria=eligibility_criteria, application_deadline=deadline_date, drive_status="pending")
        db.session.add(drive)
        db.session.commit()
        flash("Drive created and sent for admin approval.", "success")
        return redirect(url_for("company_home"))
        
    return render_template("create_drive.html", company=company)

@app.route("/company/drives/<int:drive_id>")
def drive_details(drive_id):
    company = company_check()
    if not company: return redirect(url_for("sign_in"))
    
    drive = PlacementDrive.query.filter_by(id=drive_id, company_id=company.id).first_or_404()
    applications = Application.query.filter_by(drive_id=drive.id).join(StudentUser).add_entity(StudentUser).order_by(Application.applied_on.desc()).all()
    return render_template("drive_details.html", company=company, drive=drive, applications=applications)

@app.route("/company/drives/<int:drive_id>/edit", methods=["GET", "POST"])
def edit_drive(drive_id):
    company = company_check()
    if not company: return redirect(url_for("sign_in"))
    
    drive = PlacementDrive.query.filter_by(id=drive_id, company_id=company.id).first_or_404()

    if request.method == "POST":
        action = request.form.get("action", "update")
        if action == "close":
            drive.drive_status = "closed"
        elif action == "delete":
            db.session.delete(drive)
            db.session.commit()
            flash("Drive deleted successfully.", "success")
            return redirect(url_for("company_home"))
        else:
            drive.drive_title = request.form.get("drive_title", drive.drive_title)
            drive.job_role = request.form.get("job_role", drive.job_role)
            drive.job_location = request.form.get("job_location", drive.job_location)
            drive.salary_package = request.form.get("salary_package", drive.salary_package)
            drive.job_description = request.form.get("job_description", drive.job_description)
            drive.eligibility_criteria = request.form.get("eligibility_criteria", drive.eligibility_criteria)
            deadline_str = request.form.get("application_deadline", "").strip()
            if deadline_str:
                try:
                    drive.application_deadline = datetime.strptime(deadline_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Invalid deadline format.", "warning")
                    return redirect(url_for("edit_drive", drive_id=drive.id))
                    
        db.session.commit()
        flash("Drive updated.", "success")
        return redirect(url_for("drive_details", drive_id=drive.id))
        
    return render_template("edit_drive.html", company=company, drive=drive)

@app.route("/company/applications/<int:application_id>/review", methods=["POST"])
def review_application(application_id):
    company = company_check()
    if not company: return redirect(url_for("sign_in"))
    
    application = Application.query.join(PlacementDrive).filter(Application.id == application_id, PlacementDrive.company_id == company.id).first_or_404()
    
    new_status = request.form.get("status")
    remark = request.form.get("remark", "").strip()
    valid_status = {"Applied", "Shortlisted", "Interview", "Selected", "Rejected", "Placed"}
    
    if new_status in valid_status:
        application.current_status = new_status
        application.recruiter_remark = remark
        application.last_updated = datetime.utcnow()
        db.session.commit()
        flash("Application updated.", "success")
    else:
        flash("Invalid status value.", "warning")
        
    return redirect(url_for("drive_details", drive_id=application.drive_id))


# -----------------------------------------------------------------------------
# STUDENT ROUTES
# -----------------------------------------------------------------------------
def student_check():
    if session.get("active_role") != "student":
        return None
    student_id = session.get("user_id")
    student = StudentUser.query.get(student_id)
    if not student or student.account_status == "blacklisted":
        return None
    return student

@app.route("/student/home")
def student_home():
    student = student_check()
    if not student: return redirect(url_for("sign_in"))
    
    today = date.today()
    approved_drives = PlacementDrive.query.join(CompanyAccount).filter(PlacementDrive.drive_status == "approved", PlacementDrive.application_deadline >= today, CompanyAccount.approval_state == "approved", CompanyAccount.account_state == "active").order_by(PlacementDrive.application_deadline.asc()).all()
    applied_drive_ids = {app.drive_id for app in student.applications}
    recent_applications = Application.query.filter_by(student_id=student.id).order_by(Application.applied_on.desc()).limit(10).all()
    
    return render_template("student_dashboard.html", student=student, approved_drives=approved_drives, applied_drive_ids=applied_drive_ids, recent_applications=recent_applications)

@app.route("/student/profile", methods=["GET", "POST"])
def profile():
    student = student_check()
    if not student: return redirect(url_for("sign_in"))
    
    profile = student.profile
    if request.method == "POST":
        student.full_name = request.form.get("full_name", student.full_name)
        student.phone_number = request.form.get("phone_number", student.phone_number)
        student.department = request.form.get("department", student.department)
        cgpa = request.form.get("cgpa", "").strip()
        try:
            student.cgpa = float(cgpa) if cgpa else None
        except ValueError:
            pass

        profile.skills = request.form.get("skills", profile.skills)
        profile.about_me = request.form.get("about_me", profile.about_me)
        profile.linkedin_url = request.form.get("linkedin_url", profile.linkedin_url)

        resume_file = request.files.get("resume_file")
        if resume_file and resume_file.filename:
            allowed_extensions = {".pdf", ".doc", ".docx"}
            ext = os.path.splitext(resume_file.filename)[1].lower()
            if ext not in allowed_extensions:
                flash("Invalid file type. Only PDF, DOC, and DOCX allowed.", "danger")
                return redirect(url_for("profile"))

            filename = secure_filename(resume_file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            resume_file.save(save_path)
            profile.resume_filename = filename

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))
        
    return render_template("profile.html", student=student, profile=profile)

@app.route("/student/resume/<filename>")
def resume_download(filename):
    student = student_check()
    if not student: return redirect(url_for("sign_in"))
    
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

@app.route("/student/apply/<int:drive_id>", methods=["POST"])
def apply_drive(drive_id):
    student = student_check()
    if not student: return redirect(url_for("sign_in"))
    
    drive = PlacementDrive.query.get_or_404(drive_id)

    if drive.drive_status != "approved":
        flash("You can apply only to approved drives.", "warning")
        return redirect(url_for("student_home"))

    if drive.application_deadline < date.today():
        flash("Application deadline has passed.", "warning")
        return redirect(url_for("student_home"))

    existing = Application.query.filter_by(student_id=student.id, drive_id=drive.id).first()
    if existing:
        flash("You have already applied to this drive.", "info")
        return redirect(url_for("student_home"))

    note = request.form.get("student_note", "").strip()
    application = Application(student_id=student.id, drive_id=drive.id, current_status="Applied", student_note=note)
    db.session.add(application)
    db.session.commit()
    
    flash("Application submitted.", "success")
    return redirect(url_for("student_home"))

@app.route("/student/history")
def application_history():
    student = student_check()
    if not student: return redirect(url_for("sign_in"))
    
    all_applications = db.session.query(Application, PlacementDrive, CompanyAccount).join(PlacementDrive, Application.drive_id == PlacementDrive.id).join(CompanyAccount, PlacementDrive.company_id == CompanyAccount.id).filter(Application.student_id == student.id).order_by(Application.applied_on.desc()).all()
    return render_template("placement_history.html", student=student, application_rows=all_applications)


if __name__ == "__main__":
    app.run(debug=True)