from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateTimeField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo

from datetime import datetime
from flask_mail import Mail, Message as MailMessage

from market import db, login_manager, bcrypt

from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === USER TABLE ===
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email_address = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(60), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), nullable=False, default='normal_user')  # farmer, vet, admin
    avatar_url = db.Column(db.Text, default=None)  # UPDATED: Use Text for long base64 strings
    
    
    @property
    def password(self): return self.password
    @password.setter
    def password(self, plain_text): 
        self.password_hash = bcrypt.generate_password_hash(plain_text).decode('utf-8')
    def check_password_correction(self, pwd): 
        return bcrypt.check_password_hash(self.password_hash, pwd)

    # Optional: Gravatar helper (generate URL from email)
    @property
    def gravatar_url(self):
        import hashlib
        email_hash = hashlib.md5(self.email_address.lower().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?s=80&d=identicon"  # s=80 (size), d=identicon (default icon)
    
    
# === ANIMAL TABLE ===
class Animal(db.Model):
    __tablename__ = 'Animal'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

# === VACCINE RECORD TABLE ===
class VaccineRecord(db.Model):
    __tablename__ = 'VaccineRecord'
    id = db.Column(db.Integer, primary_key=True)
    animal_id = db.Column(db.Integer, db.ForeignKey('Animal.id'), nullable=False)
    vaccine_name = db.Column(db.String(100), nullable=False)
    age_bracket = db.Column(db.String(50))
    date_given = db.Column(db.String(20))  # NULL if not given
    next_due = db.Column(db.String(20), nullable=False)  # YYYY-MM-DD

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(20), default='info')  # NEW: For styling (login, success, etc.)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Notification {self.content[:30]}>'