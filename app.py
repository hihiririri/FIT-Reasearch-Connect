from dotenv import load_dotenv
import json
import os

load_dotenv()
import secrets
import uuid
import bleach
from models import TopicApplication, AcademicWork, AcademicWorkLike, Post, PostLike, db
from flask import jsonify
from flask_login import current_user
from sqlalchemy import func
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import joinedload
from flask_mail import Mail, Message

from PIL import Image
from functools import wraps
from datetime import datetime, timezone, date
from flask import (Flask, render_template, url_for, flash, redirect, request,
                   send_from_directory, abort, jsonify, current_app)
from sqlalchemy import asc, desc, or_, MetaData
from sqlalchemy.testing.plugin.plugin_base import post
from werkzeug.utils import secure_filename
from forms import RequestPasswordResetForm, ResetPasswordForm

from models import StudentIdea, Notification, TopicApplication, AcademicWork
from extensions import db, migrate, bcrypt, login_manager
from models import (User, Post, Attachment, StudentIdea, IdeaAttachment, Notification,
                    student_topic_interest, Tag, idea_recipient_lecturers)
from forms import (LoginForm, RegistrationForm, PostForm, UpdateAccountForm,
                   ChangePasswordForm, IdeaSubmissionForm, IdeaReviewForm)
from flask_login import login_user, current_user, logout_user, login_required

app = Flask(__name__)

SECRET_KEY_FALLBACK = 'thay-doi-key-nay-ngay-lap-tuc-cho-dev-012345!'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', SECRET_KEY_FALLBACK)

if app.config['SECRET_KEY'] == SECRET_KEY_FALLBACK:
    print("\n" + "=" * 60)
    print("!!! CẢNH BÁO: Đang sử dụng SECRET_KEY dự phòng (fallback)! !!!")
    print("-> Vui lòng tạo file '.env' ở thư mục gốc và đặt giá trị")
    print("   SECRET_KEY=... với một key ngẫu nhiên mạnh của riêng bạn.")
    print("   Tạo key mới bằng: python -c \"import secrets; print(secrets.token_hex(24))\"")
    if not app.debug:
        print("\n!!! LỖI NGHIÊM TRỌNG: KHÔNG ĐƯỢC CHẠY PRODUCTION VỚI KEY FALLBACK NÀY !!!")
    print("=" * 60 + "\n")

csrf = CSRFProtect()
csrf.init_app(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')

mail = Mail(app)

DEFAULT_PICS_FOLDER = os.path.join(app.root_path, 'static', 'profile_pics')
os.makedirs(DEFAULT_PICS_FOLDER, exist_ok=True)

USER_PICS_FOLDER = os.path.join(app.root_path, 'static', 'user_pics')
os.makedirs(USER_PICS_FOLDER, exist_ok=True)

app.config['DEFAULT_PICS_FOLDER'] = DEFAULT_PICS_FOLDER
app.config['USER_PICS_FOLDER'] = USER_PICS_FOLDER

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ACADEMIC_WORK_IMAGE_FOLDER = os.path.join(app.root_path, 'static', 'academic_work_images')
os.makedirs(ACADEMIC_WORK_IMAGE_FOLDER, exist_ok=True)
app.config['ACADEMIC_WORK_IMAGE_FOLDER'] = ACADEMIC_WORK_IMAGE_FOLDER

db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

try:
    from admin_routes import admin_bp
    app.register_blueprint(admin_bp)
    print("Admin Blueprint registered.")
except ImportError:
    print("Admin Blueprint not found or not registered.")

ALLOWED_TAGS = [
    'p', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'br', 'blockquote', 'h1', 'h2', 'h3',
    'a', 'figure', 'figcaption', 'img',
    'pre', 'code', 'div', 'span'
]
ALLOWED_ATTRS = {
    '*': ['class'],
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'width', 'height']
}

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', title='Không tìm thấy trang'), 404

@app.errorhandler(403)
def forbidden_access(e):
    return render_template('403.html', title='Truy cập bị chặn'), 403

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'Đăng nhập thành công cho {user.full_name}!', 'auth')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Đăng nhập thất bại. Vui lòng kiểm tra email và mật khẩu.', 'auth')
            print("DEBUG: Flashed 'Login Failed' message.")
    return render_template('login.html', title='LogIn ', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            full_name=form.full_name.data,
            student_id=form.student_id.data,
            email=form.email.data,
            class_name=form.class_name.data,
            date_of_birth=form.date_of_birth.data,
            gender=form.gender.data,
            phone_number=form.phone_number.data,
            password_hash=hashed_password,
            role='student'
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash(f'Tài khoản sinh viên cho {form.full_name.data} đã được tạo! Bạn có thể đăng nhập.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Lỗi khi tạo tài khoản: {e}', 'danger')

    return render_template('register.html', title='Đăng ký Sinh viên', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Bạn đã đăng xuất.', 'auth')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    feat_page = request.args.get('feat_page', 1, type=int)
    selected_sort = request.args.get('sort', 'date_desc')
    selected_author_id = request.args.get('author_id', '', type=str)
    selected_post_type = request.args.get('post_type', '', type=str)
    selected_status = request.args.get('status', '', type=str)
    selected_tag_id = request.args.get('tag_id', '', type=str)
    search_query = request.args.get('q', None, type=str)

    REGULAR_PER_PAGE = 10
    FEATURED_PER_PAGE = 4

    featured_pagination = Post.query.filter_by(is_featured=True) \
        .order_by(Post.date_posted.desc()) \
        .paginate(page=feat_page, per_page=FEATURED_PER_PAGE, error_out=False)

    query = Post.query.filter(Post.is_featured == False)
    needs_user_join = False
    needs_tag_join = bool(selected_tag_id)

    if search_query:
        search_term = f"%{search_query}%"
        query = query.outerjoin(User, Post.user_id == User.id).filter(
            or_(Post.title.ilike(search_term),
                Post.content.ilike(search_term),
                User.full_name.ilike(search_term)))
        needs_user_join = True

    if selected_author_id:
        if not needs_user_join:
            query = query.join(User, Post.user_id == User.id)
            needs_user_join = True
        query = query.filter(User.id == selected_author_id)

    if selected_post_type:
        query = query.filter(Post.post_type == selected_post_type)

    if selected_status:
        if selected_post_type == 'topic':
            if selected_status in ['recruiting', 'working_on', 'closed', 'pending']:
                query = query.filter(Post.status == selected_status)
        elif selected_post_type == 'article':
            if selected_status == 'published':
                query = query.filter(Post.status == selected_status)
        elif not selected_post_type:
            if selected_status in ['published', 'closed']:
                query = query.filter(Post.status == selected_status)
            elif selected_status == 'recruiting':
                query = query.filter(Post.status == selected_status, Post.post_type == 'topic')

    if needs_tag_join:
        query = query.outerjoin(Post.tags)
        try:
            tag_id_int = int(selected_tag_id)
            query = query.filter(Post.tags.any(Tag.id == tag_id_int))
        except (ValueError, TypeError):
            selected_tag_id = ''

    if selected_sort == 'date_asc':
        query = query.order_by(Post.date_posted.asc())
    elif selected_sort == 'title_asc':
        query = query.order_by(func.lower(Post.title).asc())
    elif selected_sort == 'title_desc':
        query = query.order_by(func.lower(Post.title).desc())
    else:
        query = query.order_by(Post.date_posted.desc())

    regular_pagination = query.paginate(page=page, per_page=REGULAR_PER_PAGE, error_out=False)
    posts_on_page = regular_pagination.items
    post_ids_on_page = [p.id for p in posts_on_page if p.id is not None]

    like_counts = {}
    user_liked_posts = set()
    user_application_status = {}

    if post_ids_on_page:
        try:
            like_counts_query = db.session.query(
                PostLike.post_id, func.count(PostLike.id)
            ).filter(
                PostLike.post_id.in_(post_ids_on_page)
            ).group_by(
                PostLike.post_id
            ).all()
            like_counts = {post_id: count for post_id, count in like_counts_query}
        except Exception as e:
            print(f"Error fetching like counts for dashboard: {e}")

        if current_user.is_authenticated:
            try:
                user_likes_query = db.session.query(PostLike.post_id).filter(
                    PostLike.user_id == current_user.id,
                    PostLike.post_id.in_(post_ids_on_page)
                ).all()
                user_liked_posts = {post_id for (post_id,) in user_likes_query}
            except Exception as e:
                print(f"Error fetching user likes for dashboard: {e}")

        if current_user.is_authenticated and current_user.role == 'student':
            try:
                recruiting_topic_ids = [p.id for p in posts_on_page if
                                        p.post_type == 'topic' and p.status == 'recruiting']
                if recruiting_topic_ids:
                    user_apps_query = db.session.query(TopicApplication.post_id, TopicApplication.status).filter(
                        TopicApplication.user_id == current_user.id,
                        TopicApplication.post_id.in_(recruiting_topic_ids)
                    ).all()
                    user_application_status = {post_id: status for post_id, status in user_apps_query}
            except Exception as e:
                print(f"Error fetching user applications for dashboard: {e}")

    lecturers = User.query.filter_by(role='lecturer').order_by(User.full_name).all()
    all_tags = Tag.query.order_by(Tag.name).all()

    return render_template('dashboard.html', title='Bảng điều khiển',
                           featured_pagination=featured_pagination,
                           posts_pagination=regular_pagination,
                           lecturers=lecturers,
                           all_tags=all_tags,
                           selected_sort=selected_sort,
                           selected_author_id=selected_author_id,
                           selected_post_type=selected_post_type,
                           selected_status=selected_status,
                           selected_tag_id=selected_tag_id,
                           search_query=search_query,
                           like_counts=like_counts,
                           user_liked_posts=user_liked_posts,
                           user_application_status=user_application_status
                           )

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def create_post():
    if current_user.role != 'lecturer':
        flash('Bạn không có quyền truy cập chức năng này.', 'danger')
        return redirect(url_for('dashboard'))

    form = PostForm()

    try:
        all_tags = Tag.query.order_by(Tag.name).all()
        all_tag_names = [tag.name for tag in all_tags]
    except Exception as e:
        print(f"Lỗi khi lấy danh sách tags cho form: {e}")
        all_tag_names = []

    if form.validate_on_submit():
        safe_content = bleach.clean(form.content.data, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        post = Post(title=form.title.data, content=safe_content, post_type=form.post_type.data,
                    is_featured=form.is_featured.data, status=form.status.data, author=current_user)

        attachments_to_add = []
        saved_physical_files = []
        files_saved_count = 0
        post_id_to_assign = None

        try:
            db.session.add(post)
            db.session.flush()
            post_id_to_assign = post.id

            tags_input_value = form.tags.data
            post_tags_objects = []
            tag_names = []

            if tags_input_value:
                try:
                    tag_data_list = json.loads(tags_input_value)
                    tag_names = [
                        item['value'].strip().lower()
                        for item in tag_data_list
                        if isinstance(item, dict) and item.get('value') and str(item.get('value')).strip()
                    ]
                    print(f"DEBUG (create_post): Parsed tags from JSON: {tag_names}")

                except (json.JSONDecodeError, TypeError, ValueError):
                    print(
                        f"DEBUG (create_post): Failed to parse as JSON, treating as comma-separated: '{tags_input_value}'")
                    tag_names = [name.strip().lower() for name in str(tags_input_value).split(',') if name.strip()]
                    print(f"DEBUG (create_post): Parsed tags from string: {tag_names}")

                if tag_names:
                    existing_tags = Tag.query.filter(Tag.name.in_(tag_names)).all()
                    existing_tags_map = {tag.name: tag for tag in existing_tags}

                    for name in tag_names:
                        tag = existing_tags_map.get(name)
                        if not tag:
                            tag = Tag(name=name)
                            db.session.add(tag)
                        if isinstance(tag, Tag):
                            post_tags_objects.append(tag)

            post.tags = post_tags_objects
            print(
                f"DEBUG (create_post): Assigned Tag objects to post.tags (before commit): {[t.name for t in post.tags]}")

            if post_id_to_assign:
                if form.attachments.data and form.attachments.data[0].filename != '':
                    for file in form.attachments.data:
                        original_filename = secure_filename(file.filename)
                        if original_filename != '':
                            name, ext = os.path.splitext(original_filename)
                            unique_filename = f"{uuid.uuid4().hex}{ext}"
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                            try:
                                file.save(file_path)
                                attachment = Attachment(original_filename=original_filename,
                                                        saved_filename=unique_filename, post_id=post_id_to_assign)
                                attachments_to_add.append(attachment)
                                saved_physical_files.append(file_path)
                                files_saved_count += 1
                            except Exception as file_e:
                                flash(f'Lỗi khi lưu file {original_filename}: {file_e}.', 'warning')

                if attachments_to_add:
                    db.session.add_all(attachments_to_add)

                print("DEBUG (create_post): Attempting final commit...")
                db.session.commit()
                print("DEBUG (create_post): Final commit successful!")
                flash(f'Bài đăng đã được tạo thành công! ({files_saved_count} tệp đính kèm).', 'auth')
                return redirect(url_for('my_posts'))
            else:
                db.session.rollback()
                flash('Lỗi nghiêm trọng: Không thể lấy ID bài đăng.', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'Đã xảy ra lỗi khi tạo bài đăng: {e}', 'danger')
            for file_path in saved_physical_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as remove_err:
                        print(f"Error deleting file after create fail: {remove_err}")

    elif form.errors:
        print(f"Form validation errors (create_post): {form.errors}")

    return render_template('create_post.html', title='Tạo Bài đăng mới', form=form,
                           legend='Tạo Bài đăng / Đề tài', all_tag_names=all_tag_names)

@app.route('/uploads/<path:filename>')
@login_required
def download_file(filename):
    attachment = Attachment.query.filter_by(saved_filename=filename).first_or_404()
    download_name = attachment.original_filename or filename
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True,
                                   download_name=download_name)
    except FileNotFoundError:
        abort(404)

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)

    post_like_count = 0
    user_has_liked_post = False
    try:
        post_like_count = db.session.query(func.count(PostLike.id)) \
                              .filter(PostLike.post_id == post.id) \
                              .scalar() or 0
        if current_user.is_authenticated:
            user_like = PostLike.query.filter_by(user_id=current_user.id, post_id=post.id).first()
            if user_like: user_has_liked_post = True
    except Exception as e:
        print(f"Error fetching like info for post {post_id}: {e}")

    application = None
    if post.post_type == 'topic' and current_user.is_authenticated and current_user.role == 'student':
        try:
            application = TopicApplication.query.filter_by(
                user_id=current_user.id,
                post_id=post.id
            ).first()
        except Exception as e:
            print(f"Error fetching application info for post {post_id}, user {current_user.id}: {e}")
            application = None

    return render_template('post_detail.html',
                           title=post.title,
                           post=post,
                           application=application,
                           like_count=post_like_count,
                           user_has_liked=user_has_liked_post)

@app.route('/post/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user: abort(403)
    form = PostForm()

    try:
        all_tags = Tag.query.order_by(Tag.name).all()
        all_tag_names = [tag.name for tag in all_tags]
    except Exception as e:
        print(f"Lỗi khi lấy danh sách tags cho form update: {e}")
        all_tag_names = []

    if form.validate_on_submit():
        safe_content = bleach.clean(form.content.data, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        post.title = form.title.data
        post.content = safe_content
        post.post_type = form.post_type.data
        post.status = form.status.data
        post.is_featured = form.is_featured.data

        attachments_to_add = []
        saved_physical_files = []
        files_saved_count = 0
        old_filenames_to_delete = []
        files_were_uploaded = bool(form.attachments.data and form.attachments.data[0].filename != '')

        try:
            tags_input_value = form.tags.data
            post_tags_objects = []
            tag_names = []

            if tags_input_value:
                try:
                    tag_data_list = json.loads(tags_input_value)
                    tag_names = [
                        item['value'].strip().lower()
                        for item in tag_data_list
                        if isinstance(item, dict) and item.get('value') and str(item.get('value')).strip()
                    ]
                except (json.JSONDecodeError, TypeError, ValueError):
                    tag_names = [name.strip().lower() for name in str(tags_input_value).split(',') if name.strip()]

                if tag_names:
                    existing_tags = Tag.query.filter(Tag.name.in_(tag_names)).all()
                    existing_tags_map = {tag.name: tag for tag in existing_tags}

                    for name in tag_names:
                        tag = existing_tags_map.get(name)
                        if not tag:
                            tag = Tag(name=name)
                            db.session.add(tag)
                        if isinstance(tag, Tag):
                            post_tags_objects.append(tag)
            post.tags = post_tags_objects

            if files_were_uploaded:
                old_filenames_to_delete = [att.saved_filename for att in post.attachments]
                post.attachments = []
                for file in form.attachments.data:
                    original_filename = secure_filename(file.filename)
                    if original_filename != '':
                        name, ext = os.path.splitext(original_filename)
                        unique_filename = f"{uuid.uuid4().hex}{ext}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        try:
                            file.save(file_path)
                            attachment = Attachment(original_filename=original_filename,
                                                    saved_filename=unique_filename,
                                                    post_id=post.id)
                            attachments_to_add.append(attachment)
                            saved_physical_files.append(file_path)
                            files_saved_count += 1
                        except Exception as e:
                            flash(f'Lỗi khi lưu file mới {original_filename}.', 'warning')
            else:
                try:
                    files_saved_count = db.session.query(Attachment).filter_by(post_id=post.id).count()
                except:
                    files_saved_count = 0

            if attachments_to_add:
                db.session.add_all(attachments_to_add)

            db.session.commit()
            flash(f'Bài đăng đã được cập nhật! ({files_saved_count} tệp đính kèm).', 'success')

            if files_were_uploaded and old_filenames_to_delete:
                for filename in old_filenames_to_delete:
                    if filename:
                        old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        if os.path.exists(old_file_path):
                            try:
                                os.remove(old_file_path)
                            except Exception as e:
                                print(f"Update Error deleting old file {old_file_path}: {e}")
            return redirect(url_for('view_post', post_id=post.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Lỗi khi cập nhật bài đăng: {e}', 'danger')
            for file_path in saved_physical_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as remove_err:
                        print(f"Error deleting NEW file after commit fail: {remove_err}")

    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
        form.post_type.data = post.post_type
        form.status.data = post.status
        form.is_featured.data = post.is_featured
        current_tags_string = ', '.join([tag.name for tag in post.tags]) if post.tags else ''
        form.tags.data = current_tags_string
    elif form.errors:
        print(f"Form validation errors (update_post): {form.errors}")

    current_tags_string = ', '.join([tag.name for tag in post.tags]) if post.tags else ''

    return render_template('create_post.html', title='Cập nhật Bài đăng', form=form,
                           legend=f'Cập nhật: {post.title}', post=post,
                           all_tag_names=all_tag_names,
                           current_tags_string=current_tags_string)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user: abort(403)
    filenames_to_delete = [att.saved_filename for att in post.attachments]
    try:
        db.session.delete(post)
        db.session.commit()
        for filename in filenames_to_delete:
            if filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting post attachment file {file_path}: {e}")
        flash('Bài đăng của bạn đã được xóa!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Lỗi khi xóa bài đăng: {e}', 'danger')
    return redirect(url_for('my_posts'))

@app.route('/account')
@login_required
def account():
    cohort = None
    if current_user.role == 'student' and current_user.student_id and len(current_user.student_id) >= 2:
        try:
            cohort = f"K{current_user.student_id[:2]}"
        except:
            cohort = "N/A"
    return render_template('account_view.html', title='Thông tin Tài khoản', cohort=cohort)

def save_picture(form_picture, old_picture_filename=None):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    user_pics_dir = current_app.config.get('USER_PICS_FOLDER',
                                           os.path.join(current_app.root_path, 'static', 'user_pics'))
    picture_path = os.path.join(user_pics_dir, picture_fn)

    if old_picture_filename and not old_picture_filename.startswith('default'):
        try:
            old_picture_path = os.path.join(user_pics_dir, old_picture_filename)
            if os.path.exists(old_picture_path):
                os.remove(old_picture_path)
        except Exception as e:
            print(f"Lỗi khi xóa ảnh cũ {old_picture_path}: {e}")

    output_size = (150, 150)
    try:
        img = Image.open(form_picture)
        img.thumbnail(output_size)
        img.save(picture_path)
        return picture_fn
    except Exception as e:
        print(f"Lỗi khi lưu hoặc resize ảnh: {e}")
        return None

@app.route('/account/edit', methods=['GET', 'POST'])
@login_required
def account_edit():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        new_image_filename = None
        if form.picture.data:
            picture_file = save_picture(form.picture.data, current_user.image_file)
            if picture_file:
                new_image_filename = picture_file
                current_user.image_file = new_image_filename
                print(f"DEBUG: Assigned new image_file to current_user: {current_user.image_file}")
            else:
                flash('Đã xảy ra lỗi khi tải ảnh lên.', 'danger')

        current_user.date_of_birth = form.date_of_birth.data
        current_user.gender = form.gender.data
        current_user.phone_number = form.phone_number.data
        current_user.contact_email = form.contact_email.data if form.contact_email.data else None
        current_user.about_me = form.about_me.data
        current_user.class_name = form.class_name.data

        print(
            f"DEBUG: User object state BEFORE commit: ImageFile={current_user.image_file}, Phone={current_user.phone_number}, ...")

        try:
            print("DEBUG: Attempting db.session.commit()")
            db.session.commit()
            print("DEBUG: Commit successful.")
            flash('Thông tin tài khoản của bạn đã được cập nhật!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"!!! DEBUG: Commit FAILED in account_edit! Error: {e}")
            flash(f'Lỗi khi cập nhật thông tin: {e}', 'danger')

        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.date_of_birth.data = current_user.date_of_birth
        form.gender.data = current_user.gender
        form.phone_number.data = current_user.phone_number
        form.contact_email.data = current_user.contact_email
        form.about_me.data = current_user.about_me
        form.class_name.data = current_user.class_name
    return render_template('account_edit.html', title='Chỉnh sửa Thông tin', form=form)

@app.route('/application/<int:application_id>/withdraw', methods=['POST'])
@login_required
def withdraw_application(application_id):
    application = TopicApplication.query.get_or_404(application_id)
    if application.user_id != current_user.id: abort(403)
    if application.status != 'pending':
        flash('Bạn không thể hủy đơn đăng ký đã được xử lý.', 'warning')
        return jsonify({'status': 'error', 'message': 'Đơn đã được xử lý.'}), 400

    try:
        post_author_id = application.topic.user_id if application.topic else None
        post_title = application.topic.title if application.topic else "Không rõ"

        db.session.delete(application)

        if post_author_id:
            notification_content = f"Sinh viên {current_user.full_name} đã hủy đăng ký đề tài: '{post_title[:30]}...'"
            new_notification = Notification(
                recipient_id=post_author_id, sender_id=current_user.id,
                content=notification_content, notification_type='application_withdrawn',
                is_read=False
            )
            db.session.add(new_notification)

        db.session.commit()
        return jsonify({'status': 'success', 'applied': False, 'message': 'Đã hủy đăng ký đề tài!', })
    except Exception as e:
        db.session.rollback()
        print(f"Error withdrawing application {application_id}: {e}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi hủy đăng ký: {e}'}), 500

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        try:
            db.session.commit()
            flash('Mật khẩu của bạn đã được cập nhật thành công!', 'success')
            return redirect(url_for('account'))
        except Exception as e:
            db.session.rollback()
            flash(f'Lỗi khi cập nhật mật khẩu: {e}', 'danger')

    return render_template('change_password.html', title='Đổi Mật khẩu', form=form)

@app.route('/api/search-suggestions')
@login_required
def search_suggestions():
    query_term = request.args.get('q', '', type=str)
    suggestions = []

    if query_term and len(query_term) >= 2:
        search_pattern = f"%{query_term}%"
        posts = Post.query.join(User).filter(
            or_(
                Post.title.ilike(search_pattern),
                Post.content.ilike(search_pattern)
            )
        ).order_by(Post.date_posted.desc()).limit(10).all()

        for post in posts:
            suggestions.append({
                'id': post.id,
                'title': post.title,
                'author': post.author.full_name,
                'url': url_for('view_post', post_id=post.id)
            })
    return jsonify(suggestions)

@app.route('/search')
@login_required
def search_results():
    search_query = request.args.get('q', '', type=str)
    page = request.args.get('page', 1, type=int)
    selected_sort = request.args.get('sort', 'date_desc')
    selected_author_id = request.args.get('author_id', '', type=str)
    selected_post_type = request.args.get('post_type', '', type=str)
    selected_status = request.args.get('status', '', type=str)

    RESULTS_PER_PAGE = 10
    query = Post.query.filter_by(is_featured=False)

    if search_query:
        search_term = f"%{search_query}%"
        query = query.join(User, Post.user_id == User.id).filter(
            or_(
                Post.title.ilike(search_term),
                Post.content.ilike(search_term),
                User.full_name.ilike(search_term)
            )
        )
        needs_join = False
    else:
        needs_join = bool(selected_author_id)
        if needs_join: query = query.join(User, Post.user_id == User.id)

    if selected_author_id: query = query.filter(User.id == selected_author_id)
    if selected_post_type: query = query.filter(Post.post_type == selected_post_type)
    if selected_post_type == 'topic' and selected_status: query = query.filter(Post.status == selected_status)

    if selected_sort == 'date_asc':
        query = query.order_by(Post.date_posted.asc())
    elif selected_sort == 'title_asc':
        query = query.order_by(asc(db.func.lower(Post.title)))
    elif selected_sort == 'title_desc':
        query = query.order_by(desc(db.func.lower(Post.title)))
    else:
        query = query.order_by(Post.date_posted.desc())

    search_pagination = query.paginate(page=page, per_page=RESULTS_PER_PAGE, error_out=False)
    lecturers = User.query.filter_by(role='lecturer').order_by(User.full_name).all()

    return render_template('search_results.html',
                           title=f"Kết quả tìm kiếm cho '{search_query}'" if search_query else "Tìm kiếm",
                           q=search_query,
                           posts_pagination=search_pagination,
                           lecturers=lecturers,
                           selected_sort=selected_sort,
                           selected_author_id=selected_author_id,
                           selected_post_type=selected_post_type,
                           selected_status=selected_status
                           )

@app.route('/idea/submit', methods=['GET', 'POST'])
@login_required
def submit_idea():
    if current_user.role != 'student':
        flash('Chỉ sinh viên mới có thể gửi ý tưởng.', 'warning')
        return redirect(url_for('dashboard'))
    form = IdeaSubmissionForm()
    try:
        lecturer_choices = [(l.id, l.full_name) for l in
                            User.query.filter_by(role='lecturer').order_by(User.full_name).all()]
        form.recipients.choices = lecturer_choices
    except Exception as e:
        flash('Lỗi tải danh sách giảng viên.', 'danger')
        form.recipients.choices = []

    if form.validate_on_submit():
        safe_description = bleach.clean(form.description.data, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        idea = StudentIdea(title=form.title.data, description=safe_description, student=current_user)
        idea_id_to_assign = None
        saved_physical_files = []
        attachments_to_add = []
        files_saved_count = 0
        try:
            db.session.add(idea)
            selected_recipient_ids = form.recipients.data
            if selected_recipient_ids:
                recipients_to_add = User.query.filter(User.id.in_(selected_recipient_ids),
                                                      User.role == 'lecturer').all()
                idea.recipients = recipients_to_add
            else:
                idea.recipients = []

            db.session.flush()
            idea_id_to_assign = idea.id

            if form.attachments.data and form.attachments.data[0].filename != '':
                for file in form.attachments.data:
                    original_filename = secure_filename(file.filename)
                    if original_filename != '':
                        name, ext = os.path.splitext(original_filename)
                        unique_filename = f"{uuid.uuid4().hex}{ext}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        try:
                            file.save(file_path)
                            attachment = IdeaAttachment(original_filename=original_filename,
                                                        saved_filename=unique_filename, idea_id=idea_id_to_assign)
                            attachments_to_add.append(attachment)
                            saved_physical_files.append(file_path)
                            files_saved_count += 1
                        except Exception as file_e:
                            flash(f'Lỗi khi lưu file {original_filename}.', 'warning')
                            print(f"Error saving file {original_filename}: {file_e}")

            if attachments_to_add:
                db.session.add_all(attachments_to_add)
            db.session.commit()
            try:
                lecturers_to_notify = idea.recipients
                if lecturers_to_notify:
                    notifications_to_add = []
                    for lecturer in lecturers_to_notify:
                        notification_content = f"Sinh viên {current_user.full_name} đã gửi một ý tưởng mới: '{idea.title}'"
                        new_notification = Notification(
                            recipient_id=lecturer.id,
                            sender_id=current_user.id,
                            content=notification_content,
                            notification_type='new_idea',
                            related_idea_id=idea.id,
                            is_read=False
                        )
                        notifications_to_add.append(new_notification)

                    if notifications_to_add:
                        db.session.add_all(notifications_to_add)
                        db.session.commit()

            except Exception as notif_e:
                print(f"LỖI NGHIÊM TRỌNG khi tạo thông báo cho ý tưởng ID {idea.id}: {notif_e}")
                flash('Gửi ý tưởng thành công, nhưng có lỗi xảy ra khi tạo thông báo cho giảng viên.', 'warning')

            flash(f'Ý tưởng của bạn đã được gửi thành công! ({files_saved_count} tệp đính kèm).', 'success')
            redirect_target = 'my_ideas' if 'my_ideas' in app.view_functions else 'dashboard'
            return redirect(url_for(redirect_target))

        except Exception as e:
            db.session.rollback()
            flash(f'Lỗi khi gửi ý tưởng: {e}', 'danger')
            for file_path in saved_physical_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as remove_err:
                        print(f"Error deleting file after commit fail: {remove_err}")

    if request.method == 'POST' and not form.validate_on_submit():
        print("Form validation errors (submit_idea):", form.errors)
    return render_template('submit_idea.html', title='Gửi Ý tưởng Mới', form=form)

@app.route('/idea_uploads/<path:filename>')
@login_required
def download_idea_attachment(filename):
    attachment = IdeaAttachment.query.filter_by(saved_filename=filename).first_or_404()
    download_name = attachment.original_filename or filename
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True,
                                   download_name=download_name)
    except FileNotFoundError:
        abort(404)

@app.route('/my-ideas')
@login_required
def my_ideas():
    if current_user.role != 'student': abort(403)

    pending_ideas_query = StudentIdea.query.filter_by(
        student=current_user,
        status='pending'
    ).order_by(StudentIdea.submission_date.desc())
    pending_ideas = pending_ideas_query.all()

    responded_ideas_query = StudentIdea.query.filter(
        StudentIdea.student == current_user,
        StudentIdea.status != 'pending'
    ).order_by(StudentIdea.submission_date.desc())
    responded_ideas = responded_ideas_query.all()

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 10
    pagination = StudentIdea.query.filter_by(student=current_user).order_by(StudentIdea.submission_date.desc()) \
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template('my_ideas.html',
                           title='Ý tưởng của tôi',
                           pending_ideas=pending_ideas,
                           responded_ideas=responded_ideas)

@app.route('/my-ideas/<int:idea_id>')
@login_required
def view_my_idea(idea_id):
    idea = StudentIdea.query.get_or_404(idea_id)
    if idea.student_id != current_user.id: abort(403)
    return render_template('view_my_idea.html', title=idea.title, idea=idea)

@app.route('/my-ideas/<int:idea_id>/delete', methods=['POST'])
@login_required
def delete_my_idea(idea_id):
    idea = StudentIdea.query.get_or_404(idea_id)
    if idea.student_id != current_user.id: abort(403)
    filenames_to_delete = [att.saved_filename for att in idea.attachments]
    try:
        db.session.delete(idea)
        db.session.commit()
        for filename in filenames_to_delete:
            if filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting idea attachment file {file_path}: {e}")
        flash('Ý tưởng của bạn đã được xóa!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Lỗi khi xóa ý tưởng: {e}', 'danger')
    return redirect(url_for('my_ideas'))

@app.route('/pending-ideas')
@login_required
def view_pending_ideas():
    if current_user.role not in ['lecturer', 'admin']:
        abort(403)

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 15

    query = StudentIdea.query.filter(
        StudentIdea.status == 'pending',
        ~(
                StudentIdea.recipients.any() &
                ~StudentIdea.recipients.any(User.id == current_user.id)
        )
    )

    pagination = query.order_by(StudentIdea.submission_date.desc()) \
        .paginate(page=page, per_page=PER_PAGE, error_out=False)

    return render_template('view_ideas_list.html',
                           title='Ý tưởng Chờ Duyệt',
                           ideas_pagination=pagination,
                           list_title='Danh sách Ý tưởng Chờ Duyệt',
                           active_tab='pending')

@app.route('/idea/<int:idea_id>/review', methods=['GET', 'POST'])
@login_required
def review_idea(idea_id):
    if current_user.role != 'lecturer':
        abort(403)

    idea = StudentIdea.query.get_or_404(idea_id)
    form = IdeaReviewForm()

    if form.validate_on_submit():
        original_status = idea.status

        idea.status = form.status.data
        idea.feedback = form.feedback.data

        notification_to_add = None
        if idea.status != original_status or form.feedback.data:
            status_text = {
                'approved': 'được chấp thuận', 'rejected': 'bị từ chối',
                'reviewed': 'đã được xem xét', 'pending': 'quay lại chờ duyệt'
            }.get(idea.status, f'cập nhật thành {idea.status}')
            feedback_text = " và có phản hồi mới" if form.feedback.data else ""
            notif_content = f"Ý tưởng \"{idea.title[:30]}...\" của bạn đã {status_text}{feedback_text}."

            print(f"DEBUG: Preparing notification for User ID: {idea.student_id}")
            notification_to_add = Notification(content=notif_content,
                                               recipient_id=idea.student_id,
                                               related_idea_id=idea.id)

        try:
            if notification_to_add:
                db.session.add(notification_to_add)
                print("DEBUG: Notification added to session.")

            db.session.commit()
            print("DEBUG: db.session.commit() successful.")
            flash(f'Đã cập nhật trạng thái và phản hồi cho ý tưởng "{idea.title}".', 'success')

            if idea.status == 'pending':
                return redirect(url_for('view_pending_ideas'))
            else:
                redirect_target = 'view_responded_ideas' if 'view_responded_ideas' in app.view_functions else 'view_pending_ideas'
                return redirect(url_for(redirect_target))

        except Exception as e:
            db.session.rollback()
            print(f"!!! Error during commit: {e}")
            flash(f'Lỗi khi cập nhật ý tưởng: {e}', 'danger')

    elif request.method == 'GET':
        form.status.data = idea.status
        form.feedback.data = idea.feedback

    return render_template('review_idea.html', title=f"Review: {idea.title}",
                           idea=idea, form=form)

@app.route('/idea/<int:idea_id>/delete-by-lecturer', methods=['POST'])
@login_required
def delete_idea_by_lecturer(idea_id):
    if current_user.role != 'lecturer':
        abort(403)

    idea = StudentIdea.query.get_or_404(idea_id)
    filenames_to_delete = [att.saved_filename for att in idea.attachments]

    try:
        db.session.delete(idea)
        db.session.commit()

        for filename in filenames_to_delete:
            if filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        print(f"GV Deleted file: {file_path}")
                    except Exception as e:
                        print(f"Error deleting file {file_path} by lecturer: {e}")

        flash('Ý tưởng đã được xóa thành công!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Đã xảy ra lỗi khi xóa ý tưởng: {e}', 'danger')

    return redirect(url_for('view_pending_ideas'))

@app.route('/responded-ideas')
@login_required
def view_responded_ideas():
    if current_user.role not in ['lecturer', 'admin']:
        abort(403)

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 15

    query = StudentIdea.query.filter(
        StudentIdea.status != 'pending',
        ~(
                StudentIdea.recipients.any() &
                ~StudentIdea.recipients.any(User.id == current_user.id)
        )
    )

    pagination = query.order_by(StudentIdea.submission_date.desc()) \
        .paginate(page=page, per_page=PER_PAGE, error_out=False)

    return render_template('view_ideas_list.html',
                           title='Ý tưởng Đã Phản hồi',
                           ideas_pagination=pagination,
                           list_title='Danh sách Ý tưởng Đã Phản hồi',
                           active_tab='responded')

@app.context_processor
def inject_notifications():
    unread_count = 0
    if current_user.is_authenticated:
        try:
            unread_count = Notification.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        except Exception as e:
            print(f"Lỗi khi đếm thông báo chưa đọc: {e}")
            unread_count = 0
    return dict(unread_count=unread_count)

@app.route('/notifications')
@login_required
def notifications():
    unread_notifications = Notification.query.filter_by(recipient_id=current_user.id, is_read=False).all()
    for notif in unread_notifications:
        notif.is_read = True
    try:
        if unread_notifications:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Lỗi khi đánh dấu thông báo đã đọc: {e}")
        flash("Có lỗi xảy ra khi cập nhật trạng thái thông báo.", "warning")

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 15

    pagination = Notification.query.filter_by(recipient_id=current_user.id) \
        .order_by(Notification.timestamp.desc()) \
        .paginate(page=page, per_page=PER_PAGE, error_out=False)

    return render_template('notifications.html', title='Thông báo của bạn',
                           notifications_pagination=pagination)

@app.route('/notification/<int:notif_id>/delete', methods=['POST'])
@login_required
def delete_notification(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    if notif.recipient_id != current_user.id:
        abort(403)

    try:
        db.session.delete(notif)
        db.session.commit()
        flash('Đã xóa thông báo.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Lỗi khi xóa thông báo: {e}', 'danger')

    return redirect(url_for('notifications'))

@app.route('/notifications/delete-all', methods=['POST'])
@login_required
def delete_all_notifications():
    try:
        num_deleted = Notification.query.filter_by(recipient_id=current_user.id).delete()
        db.session.commit()
        if num_deleted > 0:
            flash(f'Đã xóa {num_deleted} thông báo.', 'success')
        else:
            flash('Không có thông báo nào để xóa.', 'info')
    except Exception as e:
        db.session.rollback()
        flash(f'Lỗi khi xóa tất cả thông báo: {e}', 'danger')

    return redirect(url_for('notifications'))

@app.route('/apply-topic/<int:post_id>', methods=['POST'])
@login_required
def apply_to_topic(post_id):
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Chỉ sinh viên mới có thể đăng ký đề tài.'}), 403

    post = Post.query.get_or_404(post_id)

    if post.post_type != 'topic' or post.status != 'recruiting':
        return jsonify(
            {'status': 'error', 'message': 'Đề tài này không hợp lệ hoặc không còn mở đăng ký.'}), 400

    existing_app = TopicApplication.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing_app:
        return jsonify({'status': 'error', 'message': 'Bạn đã đăng ký đề tài này rồi.'}), 400

    message = None
    if request.is_json:
        message = request.json.get('message', None)
    elif request.form:
        message = request.form.get('message', None)
    if message:
        message = message.strip()
        if not message:
            message = None

    application = TopicApplication(user_id=current_user.id, post_id=post.id, message=message)

    notification_content = f"Sinh viên {current_user.full_name} đã đăng ký đề tài: '{post.title}'"
    new_notification = Notification(
        recipient_id=post.user_id,
        sender_id=current_user.id,
        content=notification_content,
        notification_type='topic_application',
        is_read=False
    )

    try:
        db.session.add(application)
        db.session.add(new_notification)
        db.session.commit()
        return jsonify({'status': 'success', 'applied': True, 'message': 'Đăng ký thành công!'})
    except Exception as e:
        db.session.rollback()
        print(f"Error applying to topic {post_id} for user {current_user.id}: {e}")
        return jsonify({'status': 'error', 'message': 'Lỗi hệ thống khi đăng ký.'}), 500

@app.route('/my-posts')
@login_required
def my_posts():
    if current_user.role != 'lecturer':
        flash('Chức năng này dành cho Giảng viên.', 'info')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 10

    posts_query = Post.query.filter_by(author=current_user) \
        .order_by(Post.date_posted.desc())
    pagination = posts_query.paginate(page=page, per_page=PER_PAGE, error_out=False)

    posts_on_page = pagination.items
    post_ids_on_page = [p.id for p in posts_on_page if p.id is not None]

    like_counts = {}
    user_liked_posts = set()

    if post_ids_on_page:
        try:
            like_counts_query = db.session.query(
                PostLike.post_id, func.count(PostLike.id)
            ).filter(
                PostLike.post_id.in_(post_ids_on_page)
            ).group_by(
                PostLike.post_id
            ).all()
            like_counts = {post_id: count for post_id, count in like_counts_query}
        except Exception as e:
            print(f"Error fetching like counts for my_posts: {e}")

        try:
            user_likes_query = db.session.query(PostLike.post_id).filter(
                PostLike.user_id == current_user.id,
                PostLike.post_id.in_(post_ids_on_page)
            ).all()
            user_liked_posts = {post_id for (post_id,) in user_likes_query}
        except Exception as e:
            print(f"Error fetching user likes for my_posts: {e}")

    return render_template('my_posts.html',
                           title='Bài đăng của tôi',
                           posts_pagination=pagination,
                           like_counts=like_counts,
                           user_liked_posts=user_liked_posts)

@app.route('/post/<int:post_id>/applications')
@login_required
def view_topic_applications(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        abort(403)

    if post.post_type != 'topic':
        flash('Chức năng này chỉ áp dụng cho Đề tài Nghiên cứu.', 'warning')
        return redirect(url_for('view_post', post_id=post.id))

    try:
        applications = post.applications.order_by(TopicApplication.application_date.asc()).all()
    except Exception as e:
        print(f"Lỗi khi query applications cho post {post.id}: {e}")
        applications = []
        flash("Lỗi khi tải danh sách đơn đăng ký.", "danger")

    return render_template('topic_applications.html',
                           title=f"Đơn đăng ký: {post.title}",
                           post=post,
                           applications=applications)

@app.route('/application/<int:application_id>/update_status', methods=['POST'])
@login_required
def update_application_status(application_id):
    application = TopicApplication.query.get_or_404(application_id)
    post = application.topic

    if post.author != current_user:
        abort(403)

    new_status = request.form.get('status')

    if new_status not in ['accepted', 'rejected']:
        flash('Trạng thái cập nhật không hợp lệ.', 'danger')
        return redirect(url_for('view_topic_applications', post_id=post.id))

    application.status = new_status

    if new_status == 'accepted':
        pass

    student_recipient = application.student
    if student_recipient:
        status_text = "chấp thuận" if new_status == 'accepted' else "từ chối"
        notif_content = f"Đăng ký của bạn cho đề tài \"{post.title[:30]}...\" đã được {status_text}."

        new_notification = Notification(
            recipient_id=student_recipient.id,
            sender_id=current_user.id,
            content=notif_content,
            notification_type='application_update',
            is_read=False
        )
        db.session.add(new_notification)

    try:
        db.session.commit()
        flash(f'Đã cập nhật trạng thái đơn đăng ký thành "{new_status}".', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Lỗi khi cập nhật trạng thái: {e}', 'danger')

    return redirect(url_for('view_topic_applications', post_id=post.id))

@app.route('/showcase', endpoint='view_all_showcase_items_explicit')
def showcase():
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('item_type', None)
    filter_year = request.args.get('year', None, type=int)

    GRID_PER_PAGE = 9
    CAROUSEL_LIMIT = 5

    try:
        carousel_items = AcademicWork.query.filter_by(is_published=True, is_featured=True) \
            .order_by(AcademicWork.date_added.desc()) \
            .limit(CAROUSEL_LIMIT).all()
    except Exception as e:
        print(f"Lỗi khi query carousel items: {e}")
        carousel_items = []

    try:
        query = AcademicWork.query.filter_by(is_published=True)
        if filter_type:
            query = query.filter(AcademicWork.item_type == filter_type)
        if filter_year:
            query = query.filter(AcademicWork.year == filter_year)

        query = query.order_by(AcademicWork.year.desc().nullslast(), AcademicWork.date_added.desc())
        items_pagination = query.paginate(page=page, per_page=GRID_PER_PAGE, error_out=False)
    except Exception as e:
        print(f"Lỗi khi query grid items: {e}")
        items_pagination = None
        flash("Lỗi khi tải danh sách công trình.", "danger")

    try:
        distinct_types = db.session.query(AcademicWork.item_type) \
            .filter(AcademicWork.is_published == True) \
            .distinct().order_by(AcademicWork.item_type).all()
        distinct_years = db.session.query(AcademicWork.year) \
            .filter(AcademicWork.is_published == True, AcademicWork.year != None) \
            .distinct().order_by(AcademicWork.year.desc()).all()
    except Exception as e:
        print(f"Lỗi khi lấy distinct filters: {e}")
        distinct_types = []
        distinct_years = []

    return render_template('showcase_list.html',
                           title="Công trình Tiêu biểu",
                           carousel_items=carousel_items,
                           items_pagination=items_pagination,
                           distinct_types=[t[0] for t in distinct_types],
                           distinct_years=[y[0] for y in distinct_years],
                           filter_type=filter_type,
                           filter_year=filter_year)

@app.route('/showcase/<int:item_id>')
def showcase_detail(item_id):
    item = AcademicWork.query.filter_by(id=item_id, is_published=True).first_or_404()
    like_count = 0
    user_has_liked = False

    try:
        like_count = db.session.query(func.count(AcademicWorkLike.id)) \
                         .filter(AcademicWorkLike.academic_work_id == item.id) \
                         .scalar() or 0
        if current_user.is_authenticated:
            user_like = AcademicWorkLike.query.filter_by(
                user_id=current_user.id,
                academic_work_id=item.id
            ).first()
            if user_like:
                user_has_liked = True
    except Exception as e:
        print(f"Lỗi khi lấy thông tin like cho showcase item {item_id}: {e}")

    return render_template('showcase_detail.html',
                           title=item.title,
                           item=item,
                           like_count=like_count,
                           user_has_liked=user_has_liked)

@app.route('/showcase/<int:item_id>/toggle_like', methods=['POST'])
@login_required
def toggle_showcase_like(item_id):
    item = AcademicWork.query.get_or_404(item_id)
    like = AcademicWorkLike.query.filter_by(
        user_id=current_user.id,
        academic_work_id=item.id
    ).first()

    user_liked_now = False
    try:
        if like:
            db.session.delete(like)
            user_liked_now = False
        else:
            new_like = AcademicWorkLike(user_id=current_user.id, academic_work_id=item.id)
            db.session.add(new_like)
            user_liked_now = True
        db.session.commit()
        like_count = AcademicWorkLike.query.filter_by(academic_work_id=item.id).count()
        return jsonify({
            'status': 'success',
            'liked': user_liked_now,
            'like_count': like_count
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error in toggle_showcase_like for item {item_id}, user {current_user.id}: {e}")
        return jsonify({'status': 'error', 'message': 'Đã xảy ra lỗi, vui lòng thử lại.'}), 500

@app.route('/post/<int:post_id>/toggle_like', methods=['POST'])
@login_required
def toggle_post_like(post_id):
    post = Post.query.get_or_404(post_id)
    like = PostLike.query.filter_by(
        user_id=current_user.id,
        post_id=post.id
    ).first()

    user_liked_now = False
    try:
        if like:
            db.session.delete(like)
            user_liked_now = False
        else:
            new_like = PostLike(user_id=current_user.id, post_id=post.id)
            db.session.add(new_like)
            user_liked_now = True
        db.session.commit()
        like_count = PostLike.query.filter_by(post_id=post.id).count()
        return jsonify({'status': 'success', 'liked': user_liked_now, 'like_count': like_count})
    except Exception as e:
        db.session.rollback()
        print(f"Error toggling like for post {post_id}, user {current_user.id}: {e}")
        return jsonify({'status': 'error', 'message': 'Đã xảy ra lỗi khi xử lý lượt thích.'}), 500

@app.route('/my-applications')
@login_required
def my_applications():
    if current_user.role != 'student':
        abort(403)

    page = request.args.get('page', 1, type=int)
    PER_PAGE = 15

    applications_query = TopicApplication.query.filter_by(user_id=current_user.id) \
        .options(
        joinedload(TopicApplication.topic).joinedload(Post.author)
    ) \
        .order_by(TopicApplication.application_date.desc())

    pagination = applications_query.paginate(page=page, per_page=PER_PAGE, error_out=False)

    return render_template('my_applications.html',
                           title='Đề tài Đã Đăng ký',
                           applications_pagination=pagination)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg_title = "Password Reset Request - FIT Research Connect"
    sender_email = current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    msg = Message(msg_title,
                  sender=sender_email,
                  recipients=[user.email])
    msg.body = f'''To reset your password for FIT Research Connect, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
This link is valid for 30 minutes.
'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        return False

@app.route("/request_password_reset", methods=['GET', 'POST'])
def request_password_reset():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if send_password_reset_email(user):
                flash(
                    'An email has been sent with instructions to reset your password. Please check your inbox (and spam folder).',
                    'info')
            else:
                flash('There was an error sending the password reset email. Please try again later or contact support.',
                      'danger')
        else:
            flash(
                'If an account with that email exists, a password reset link has been sent. Please check your inbox (and spam folder).',
                'info')
        return redirect(url_for('login'))

    return render_template('auth/request_reset_token.html',
                           title='Request Password Reset',
                           form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_password_token(token)
    if user is None:
        flash('That is an invalid or expired token. Please request a new password reset.', 'warning')
        return redirect(url_for('request_password_reset'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        try:
            db.session.commit()
            flash('Your password has been updated! You are now able to log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resetting password for user {user.id}: {e}")
            flash('An error occurred while resetting your password. Please try again.', 'danger')

    return render_template('auth/reset_password_form.html',
                           title='Reset Your Password',
                           form=form,
                           token=token)

if __name__ == '__main__': app.run(debug=True)
