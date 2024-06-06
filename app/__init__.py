from flask import Flask, render_template, request, redirect, abort, url_for, flash, send_from_directory
from flask_login import login_required, current_user, LoginManager, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

import config
import os

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def create_app(config=config.Config):
    app = Flask(__name__)
    app.config.from_object(config)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = '/index'

    from .models import User, Profile, Category, Complaint, Reply

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter(User.id == user_id).first()

    @app.route('/')
    def index():
        return redirect(url_for('login'))

    @app.get('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if not firstname or not lastname:
                flash('Please enter your first and last names.', 'danger')
                return redirect(url_for('signup'))

            if not password or not email:
                flash('Please enter your password and your email address')
                return redirect(url_for('signup'))

            if password != confirm_password:
                return redirect(url_for('signup'))

            else:
                user = User(firstname=firstname, lastname=lastname, email=email, password=password)
                user.hash_password()
                db.session.add(user)
                db.session.commit()
                profiles = Profile(user_id=user.id, fullname=f'{firstname} {lastname}', email=user.email, avatar='',
                                   password=user.password, phone='', about='')
                db.session.add(profiles)
                db.session.commit()
                return redirect(url_for('client_home'))
        else:
            return render_template('front/signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            if not password or not email:
                flash('Email and password is required', 'is-danger')
                return redirect(url_for('login'))

            user = User.query.filter_by(email=email).first()
            if not user:
                flash('This user is not signed up yet', 'is-danger')
                return redirect(url_for('login'))

            if not user.check_password(password):
                flash('password not available', 'is-danger')
                return redirect(url_for('login'))

            else:
                login_user(user)
                if user.role == 'admin':
                    return redirect(url_for('admin_home'))
                else:
                    return redirect(url_for('client_home'))

        else:
            return render_template('front/login.html')

    @app.route('/admin_home')
    @login_required
    def admin_home():
        return render_template('admin/admin_home.html', user=current_user)

    @app.route('/client_home')
    @login_required
    def client_home():
        return render_template('client/client_home.html', user=current_user)

    @app.route('/admin_layout')
    @login_required
    def admin_layout():
        return render_template('layouts/admin-layout.html')

    @app.route('/client_layout')
    @login_required
    def client_layout(user_id):
        user = User.query.filter_by(id=user_id).first()
        return render_template('layouts/client_layout.html', user_id=user_id, user=user)

    @app.get('/admin_dashboard')
    @login_required
    def dashboard():
        if current_user.role == 'admin':
            complaints = Complaint.query.all()
        else:
            complaints = Complaint.query.filter_by(user_id=current_user.id).all()
        return render_template('admin/dashboard.html', complaints=complaints)

    @app.route('/admin_profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        if request.method == 'POST':
            profile = Profile.query.filter_by(user_id=current_user.id).first()
            if not profile:
                abort(404)

            else:
                fullname = request.form.get('fullname')
                phone = request.form.get('phone')
                about = request.form.get('about')
                new_password = request.form.get('new_password')
                user = User.query.filter_by(id=current_user.id).first()
                if new_password and not user.check_password(new_password):
                    user.password = new_password
                    user.hash_password()
                profile.fullname = fullname
                profile.phone = phone
                profile.about = about
                db.session.commit()
                return redirect(url_for('dashboard'))
        else:
            profile = Profile.query.filter_by(user_id=current_user.id).first()
            return render_template('admin/profile.html', title='Profile', profile=profile)

    @app.route('/complaint', methods=['GET', 'POST'])
    @login_required
    def complaint():
        if request.method == 'POST':
            description = request.form.get('description')
            category_id = request.form.get('category_id')
            user_id = current_user.id
            complaint = Complaint(description=description, category_id=category_id, user_id=user_id)
            db.session.add(complaint)
            db.session.commit()
            return redirect(url_for('client_dashboard', user_id=user_id))

        else:
            categories = Category.query.all()
            return render_template('client/complaint.html', title='Complaint',
                                   categories=categories)

    @app.route('/reply/<int:complaint_id>', methods=['GET', 'POST'])
    @login_required
    def reply(complaint_id):
        complaint = Complaint.query.get_or_404(complaint_id)

        if request.method == 'POST':
            description = request.form.get('description')

            reply = Reply(complaint_id=complaint.id, description=description, user_id=current_user.id)
            db.session.add(reply)
            db.session.commit()
            return redirect(url_for('dashboard'))

        else:
            return render_template('admin/reply.html', title='Reply', complaint=complaint)

    @app.route('/upload-profile', methods=['GET', 'POST'])
    @login_required
    def upload_profile():
        if request.method == 'POST':
            file = request.files.get('avatar', None)
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('dashboard', user_id=current_user.id))
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile = Profile.query.filter(Profile.user_id == current_user.id).first()
                if profile:
                    profile.avatar = filename
                    db.session.commit()
                return redirect(url_for('dashboard', user_id=current_user.id))
        else:
            flash('File type not allowed')
            return redirect(url_for('profile'))

    @app.route('/uploads/<name>')
    def file_uploads(name):
        return send_from_directory(app.config["UPLOAD_FOLDER"], name)

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('admin/404.html')

    return app
