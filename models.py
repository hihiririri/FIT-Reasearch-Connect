from datetime import datetime, timezone
from extensions import db, bcrypt
from flask_login import UserMixin
from sqlalchemy import Date
from flask import current_app
from itsdangerous import URLSafeTimedSerializer as Serializer

idea_recipient_lecturers = db.Table('idea_recipient_lecturers',
                                    db.Column('student_idea_id', db.Integer,
                                              db.ForeignKey('student_idea.id', ondelete='CASCADE'), primary_key=True),
                                    db.Column('lecturer_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                                              primary_key=True)
                                    )

student_topic_interest = db.Table('student_topic_interest',
                                  db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                                            primary_key=True),
                                  db.Column('post_id', db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'),
                                            primary_key=True)
                                  )

post_tags = db.Table('post_tags',
                     db.Column('post_id', db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), primary_key=True),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True)
                     )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), unique=True, nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(128), nullable=False, default='default.jpg')
    gender = db.Column(db.String(10), nullable=True)
    password_hash = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='student')
    class_name = db.Column(db.String(50), nullable=True)
    date_of_birth = db.Column(Date, nullable=True)
    phone_number = db.Column(db.String(20), unique=False, nullable=True)
    contact_email = db.Column(db.String(120), unique=True, nullable=True)
    about_me = db.Column(db.Text, nullable=True)

    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    received_ideas = db.relationship('StudentIdea', secondary=idea_recipient_lecturers, lazy='dynamic',
                                     back_populates='recipients')
    ideas_submitted = db.relationship('StudentIdea', backref='student', lazy='dynamic',
                                      foreign_keys='StudentIdea.student_id', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='recipient', lazy='dynamic',
                                     foreign_keys='Notification.recipient_id',
                                    order_by='Notification.timestamp.desc()',
                                    cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_sec=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_password_token(token, expires_sec=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
        except Exception as e:
            current_app.logger.warning(f"Password reset token verification failed: {e}")
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.full_name}', '{self.email}', '{self.role}')"

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)

    def __repr__(self):
        return f'<Tag {self.name}>'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    content = db.Column(db.Text, nullable=False)
    is_featured = db.Column(db.Boolean, default=False)
    post_type = db.Column(db.String(10), nullable=False, default='article')
    status = db.Column(db.String(20), nullable=True, default='pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    attachments = db.relationship('Attachment', backref='post', lazy=True, cascade='all, delete-orphan')
    tags = db.relationship('Tag', secondary=post_tags, lazy='dynamic',
                           backref=db.backref('posts', lazy='dynamic'))

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(150), nullable=False)
    saved_filename = db.Column(db.String(100), unique=True, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"Attachment('{self.original_filename}', Post ID: {self.post_id})"

class StudentIdea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    submission_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), nullable=False, default='pending')
    feedback = db.Column(db.Text, nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    attachments = db.relationship('IdeaAttachment', backref='idea', lazy=True, cascade='all, delete-orphan')
    recipients = db.relationship('User', secondary=idea_recipient_lecturers, lazy='dynamic',
                                 back_populates='received_ideas')

    def __repr__(self):
        return f"StudentIdea('{self.title}', Status: {self.status})"

class IdeaAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(150), nullable=False)
    saved_filename = db.Column(db.String(100), unique=True, nullable=False)
    idea_id = db.Column(db.Integer, db.ForeignKey('student_idea.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"IdeaAttachment('{self.original_filename}', Idea ID: {self.idea_id})"

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    related_idea_id = db.Column(db.Integer, db.ForeignKey('student_idea.id', ondelete='SET NULL'), nullable=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    notification_type = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f"Notification('{self.content[:30]}...', Read: {self.is_read})"

class TopicApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    message = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)

    student = db.relationship('User', backref=db.backref('topic_applications', lazy='dynamic'))
    topic = db.relationship('Post', backref=db.backref('applications', lazy='dynamic'))

    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='uq_user_post_application'),)
    processed_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<TopicApplication User {self.user_id} -> Post {self.post_id} ({self.status})>'

class AcademicWork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    is_featured = db.Column(db.Boolean, default=False, nullable=False, server_default='0',index=True)
    item_type = db.Column(db.String(20), nullable=False, default='thesis', index=True)
    authors_text = db.Column(db.String(300), nullable=False)
    year = db.Column(db.Integer, nullable=True, index=True)
    abstract = db.Column(db.Text, nullable=True)
    full_content = db.Column(db.Text, nullable=True)
    image_file = db.Column(db.String(128), nullable=True)
    external_link = db.Column(db.String(255), nullable=True)
    is_published = db.Column(db.Boolean, default=False, nullable=False, index=True)
    date_added = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)

    def __repr__(self):
        return f'<AcademicWork {self.id}: {self.title[:50]}>'

class AcademicWorkLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    academic_work_id = db.Column(db.Integer, db.ForeignKey('academic_work.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('showcase_likes', lazy='dynamic', cascade='all, delete-orphan'))
    academic_work = db.relationship('AcademicWork', backref=db.backref('likes', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (db.UniqueConstraint('user_id', 'academic_work_id', name='uq_user_academic_work_like'),)

    def __repr__(self):
        return f'<AcademicWorkLike User {self.user_id} liked Item {self.academic_work_id}>'

class PostLike(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
        post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
        timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

        user = db.relationship('User', backref=db.backref('post_likes', lazy='dynamic', cascade='all, delete-orphan'))
        post = db.relationship('Post', backref=db.backref('likes', lazy='dynamic', cascade='all, delete-orphan'))

        __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='uq_user_post_like'),)

        def __repr__(self):
            return f'<PostLike User {self.user_id} liked Post {self.post_id}>'