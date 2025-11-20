import os
import smtplib
import ssl
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import check_password_hash, generate_password_hash
from market.forms import VetForm, RegisterForm, LoginForm, ChatForm, CampaignForm, TipForm, GeneralInfoForm
from flask_mail import Message as MailMessage
from uuid import uuid4
import sqlite3
from datetime import datetime
from sqlalchemy.sql import func
from email.message import EmailMessage
from flask_mail import Message, Mail
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import request, Blueprint, flash, get_flashed_messages, jsonify, redirect, render_template, request, url_for, session
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from market import app, bcrypt, db, login_manager
from market.models import User, Animal, VaccineRecord, Notification
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash
import google.generativeai as genai
# Configure logging
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
mail = Mail(app)
# Gemini
genai.configure(api_key="AIzaSyBN18RYCafdgAUmubBCiHftGu5DyL5NVS0") # ← Get from aistudio.google.com
gemini_model = genai.GenerativeModel('gemini-1.5-flash')
DB_PATH = 'market.db'
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
# ——— ROUTES ———
# NEW CODE ADDED: Email Reminder
def send_due_email(to_email, animal_name, vaccine, due_date):
    msg = Message(
        subject="Vaccine Due Reminder",
        recipients=[to_email],
        sender=app.config['MAIL_USERNAME']
    )
    msg.body = f"""
    Hello,
    Your animal **{animal_name}** needs **{vaccine}**.
    Due Date: {due_date}
    — Livestock System
    """
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Email failed: {e}")
# NEW CODE ADDED: Daily Email Check
def daily_email_check():
    with app.app_context():
        today = date.today().strftime('%Y-%m-%d')
        due = VaccineRecord.query.filter(
            VaccineRecord.next_due <= today,
            VaccineRecord.date_given.is_(None)
        ).all()
        for v in due:
            animal = Animal.query.get(v.animal_id)
            farmer = User.query.filter_by(role='farmer').first()
            if farmer and farmer.email_address:
                send_due_email(farmer.email_address, animal.name, v.vaccine_name, v.next_due)
scheduler = BackgroundScheduler()
scheduler.add_job(func=daily_email_check, trigger="cron", hour=8)
scheduler.start()
# NEW CODE ADDED: Routes
@app.route('/api/schedule')
@login_required
def api_schedule():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT a.id AS animal_id, a.name AS animal_name,
               vr.vaccine_name, vr.age_bracket, vr.date_given, vr.next_due
        FROM Animal a
        LEFT JOIN VaccineRecord vr ON vr.animal_id = a.id
        ORDER BY a.name
    """)
    rows = cur.fetchall()
    conn.close()
    animals = {}
    for r in rows:
        aid = r['animal_id']
        if aid not in animals:
            animals[aid] = {
                'animal_id': aid,
                'animal_name': r['animal_name'],
                'species': 'Unknown',
                'vaccines': []
            }
        if r['vaccine_name']:
            status = 'done' if r['date_given'] else 'upcoming'
            animals[aid]['vaccines'].append({
                'vaccine_name': r['vaccine_name'],
                'age_bracket': r['age_bracket'],
                'next_due': r['next_due'],
                'status': status
            })
    return jsonify({'animals': list(animals.values())})
@app.route('/api/schedule/done', methods=['POST'])
@login_required
def mark_done():
    if current_user.role not in ['vet', 'admin']:
        return jsonify(error="Vets only"), 403
    data = request.json
    today = date.today().strftime('%Y-%m-%d')
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE VaccineRecord SET date_given = ? WHERE animal_id = ? AND vaccine_name = ?",
                (today, data['animal_id'], data['vaccine_name']))
    conn.commit()
    conn.close()
    return jsonify(success=True)
@app.route('/vet/dashboard')
@login_required
def vet_dashboard():
    if current_user.role not in ['vet', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('main.home_page'))
    form_animal = AddAnimalForm()
    form_vaccine = AddVaccineForm()
    animals = Animal.query.all()
    form_vaccine.animal_id.choices = [(a.id, a.name) for a in animals]
    if 'add_animal' in request.form and form_animal.validate_on_submit():
        animal = Animal(name=form_animal.name.data)
        db.session.add(animal)
        db.session.commit()
        flash("Animal added!", "success")
        return redirect(url_for('vacc.vet_dashboard'))
    if 'add_vaccine' in request.form and form_vaccine.validate_on_submit():
        record = VaccineRecord(
            animal_id=form_vaccine.animal_id.data,
            vaccine_name=form_vaccine.vaccine_name.data,
            age_bracket=form_vaccine.age_bracket.data,
            next_due=form_vaccine.next_due.data.strftime('%Y-%m-%d')
        )
        db.session.add(record)
        db.session.commit()
        flash("Vaccine added!", "success")
        return redirect(url_for('vacc.vet_dashboard'))
    today = date.today().strftime('%Y-%m-%d')
    due = VaccineRecord.query.filter(
        VaccineRecord.next_due <= today,
        VaccineRecord.date_given.is_(None)
    ).all()
    return render_template('vet_dashboard.html', form_animal=form_animal, form_vaccine=form_vaccine, animals=animals, due=due)
       
@app.route('/api/ai', methods=['POST'])
@login_required
def ai_advisor():
    if current_user.role not in ['vet', 'admin']:
        return jsonify(response="AI for vets only"), 403
    query = request.json.get('query', '').strip()
    if not query:
        return jsonify(response="Ask a question.")
    try:
        response = gemini_model.generate_content(
            f"Livestock vet. 2 sentences: {query}",
            generation_config=genai.types.GenerationConfig(max_output_tokens=100)
        )
        return jsonify(response=response.text.strip())
    except Exception as e:
        return jsonify(response="AI unavailable")
@app.route('/vaccination/pdf')
@login_required
def pdf_export():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM Animals")
    animals = [dict(r) for r in cur.fetchall()]
    conn.close()
    html = render_template('vaccination_pdf.html', animals=animals)
    pdf = HTML(string=html).write_pdf()
    return send_file(BytesIO(pdf), download_name="Vaccination_Schedule.pdf", as_attachment=True)
@app.route('/')
def welcome_page():
    return render_template('welcome-page.html')
@app.route('/home')
def home_page():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    else:
        unread_count = 0
    return render_template('home.html', unread_count=unread_count)
    # we went on to call the home.html file as can be seen above.
    # 'render_template()' basically works by rendering files.
#@login_required
#below list of dictionaries is sent to the market page through the market.html
# but we are going to look for a way to store information inside an organized
# DATABASE which can be achieved through configuring a few things in our flask
# application
# WE ARE THUS GOING TO USE SQLITE3 is a File WHich allows us to store information and we are going to
# connect it to the Flask APplication.We thus have to install some flask TOOL THAT ENABLES THIS through the terminal
# Email configuration
email_sender = 'magero833@gmail.com'
EMAIL_PASSWORD = "dbvw amge uzvr secp" # App-specific password for Gmail
# Token generator for email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
# VetConnect Alerts
def send_vetconnect_alert(recipient_email, subject, body):
    from market import mail
    msg = MailMessage(subject=subject, recipients=[recipient_email], body=body)
    try:
        mail.send(msg)
        print(f"Sent alert to {recipient_email}: {subject}")
    except Exception as e:
        print(f"Failed to send alert to {recipient_email}: {e}")
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification')
def verify_verification_token(token, expiration=3600): # 1 hour expiration
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
        return email
    except SignatureExpired:
        return None # Token expired
    except BadSignature:
        return None # Invalid token
#E-mail Verification on Account Creation
def send_verification_email(email_receiver, username, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    subject = 'Verify Your Email to Create Your Account'
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                text-align: center;
                padding: 20px 0;
                background-color: #D2B48C;
                color: white;
                border-radius: 8px 8px 0 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 20px;
                color: #333;
            }}
            .content p {{
                line-height: 1.6;
                margin: 10px 0;
            }}
            .button {{
                display: inline-block;
                padding: 12px 25px;
                background-color: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                text-align: center;
            }}
            .button:hover {{
                background-color: #45a049;
            }}
            .footer {{
                text-align: center;
                padding: 10px;
                font-size: 12px;
                color: #777;
            }}
            .link {{
                word-break: break-all;
                color: #4CAF50;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://livestockanalytics.com/hs-fs/hubfs/Logos%20e%20%C3%ADconos/livestock.png?width=115&height=70&name=livestock.png" alt="Livestock Management" style="max-width: 150px;">
                <h1>Welcome to Livestock Management</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>Thank you for joining the Livestock Management System! To complete your account creation, please verify your email by clicking the button below:</p>
                <p style="text-align: center;">
                    <a href="{verification_url}" class="button">Create Account</a>
                </p>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p><a href="{verification_url}" class="link">{verification_url}</a></p>
                <p>This link expires in 1 hour.</p>
            </div>
            <div class="footer">
                <p>&copy; 2025 Livestock Management System. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body, subtype='html')  # Ensure HTML subtype is set

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, EMAIL_PASSWORD)
            smtp.sendmail(email_sender, email_receiver, em.as_string())
        print(f"Verification email sent to {email_receiver}")
    except Exception as e:
        print(f"Email error: {str(e)}")
# Email sending function for appointment confirmation
def send_appointment_email(email_receiver, vet_name, appointment_date, appointment_time, animal_type, owner_name):
    subject = 'Appointment Confirmation - Livestock Management System'
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                text-align: center;
                padding: 20px 0;
                background-color: #D2B48C;
                color: white;
                border-radius: 8px 8px 0 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 20px;
                color: #333;
            }}
            .content p {{
                line-height: 1.6;
                margin: 10px 0;
            }}
            .footer {{
                text-align: center;
                padding: 10px;
                font-size: 12px;
                color: #777;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://livestockanalytics.com/hs-fs/hubfs/Logos%20e%20%C3%ADconos/livestock.png?width=115&height=70&name=livestock.png" alt="Livestock Management" style="max-width: 150px;">
                <h1>Livestock Management System</h1>
            </div>
            <div class="content">
                <p>Hello {owner_name},</p>
                <p>Your appointment has been successfully booked with <strong>{vet_name}</strong> on <strong>{appointment_date}</strong> at <strong>{appointment_time}</strong> for your <strong>{animal_type}</strong>.</p>
                <p>We look forward to assisting you! If you need to reschedule or cancel, please contact us.</p>
            </div>
            <div class="footer">
                <p>© 2025 Livestock Management System. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body, subtype='html')

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, EMAIL_PASSWORD)
            smtp.sendmail(email_sender, email_receiver, em.as_string())
        app.logger.info(f"Appointment confirmation email sent to {email_receiver}")
    except Exception as e:
        app.logger.error(f"Email error: {str(e)}")
        raise
def send_subscription_confirmation_email(email, username):
    msg = Message(
        subject="Welcome to Livestock Management System!",
        recipients=[email],
        body=f"""
        Hello {username},
        Thank you for subscribing to the Livestock Management System! You'll now receive notifications about upcoming livestock events, campaigns, tips, and other communications.
        If you did not sign up for this, please ignore this email or contact us at support@livestockmgmt.com.
        Best regards,
        The Livestock Management Team
        """
    )
    mail.send(msg)
   
   
   
def send_event_notifications():
    with app.app_context():
        events = Event.query.filter_by(sent=False).all()
        subscribers = User.query.filter_by(role='subscriber').all()
        for event in events:
            for subscriber in subscribers:
                msg = Message(
                    subject=f"Upcoming Event: {event.title}",
                    recipients=[subscriber.email_address],
                    body=f"""
                    Hello {subscriber.username},
                    We have an upcoming event for you!
                    **{event.title}**
                    Date: {event.event_date.strftime('%Y-%m-%d')}
                    Details: {event.content}
                    Best regards,
                    The Livestock Management Team
                    To unsubscribe, click here: {url_for('unsubscribe', email=subscriber.email_address, _external=True)}
                    """
                )
                try:
                    mail.send(msg)
                except Exception as e:
                    app.logger.error(f"Failed to send event email to {subscriber.email_address}: {str(e)}")
            event.sent = True
            db.session.commit()
scheduler = BackgroundScheduler()
scheduler.add_job(func=send_event_notifications, trigger="interval", hours=24)
scheduler.start()
import atexit
atexit.register(lambda: scheduler.shutdown())
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        # Debug: Print the submitted role to verify
        print(f"Submitted role: {form.role.data}")
        # Check for existing username or email
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", category='danger')
            return render_template('register.html', form=form)
        if User.query.filter_by(email_address=form.email_address.data).first():
            flash("Email already exists.", category='danger')
            return render_template('register.html', form=form)
        # Create new user with the selected role
        new_user = User(
            username=form.username.data,
            email_address=form.email_address.data,
            password_hash=generate_password_hash(form.password1.data),
            role=form.role.data,
            email_verified=False
        )
        db.session.add(new_user)
        db.session.commit()
       
       
        # Generate verification token and send email
        token = generate_verification_token(new_user.email_address)
        try:
            send_verification_email(new_user.email_address, new_user.username, token)
            flash("Account created! Please check your email to verify your account.", category='success')
        except Exception as e:
            flash("Failed to send verification email. Please try again later.", category='danger')
            print(f"Email sending failed: {str(e)}")
            # Optionally delete the user if email fails
            db.session.delete(new_user)
            db.session.delete(notification)
            db.session.commit()
            return render_template('register.html', form=form)
        # Redirect to verify pending page for new users
        return redirect(url_for('verify_pending', email=new_user.email_address))
    return render_template('register.html', form=form)
@app.route('/verify-pending/<email>')
def verify_pending(email):
    return render_template('verify_pending.html', email=email)
@app.route('/resend-verification/<email>')
def resend_verification(email):
    user = User.query.filter_by(email_address=email, email_verified=False).first()
    if user:
        token = generate_verification_token(user.email_address) # Assume this function exists
        try:
            send_verification_email(user.email_address, user.username, token)
            flash("A new verification email has been sent!", category='info')
        except Exception as e:
            flash("Failed to send verification email. Please try again later.", category='danger')
            print(f"Email sending failed: {str(e)}")
    else:
        flash("No unverified account found for this email.", category='danger')
    return redirect(url_for('verify_pending', email=email))
@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    email = verify_verification_token(token)
    if not email:
        flash("The verification link is invalid or has expired.", category='danger')
        return redirect(url_for('login_page'))
    user = User.query.filter_by(email_address=email).first()
    if not user:
        flash("User not found.", category='danger')
        return redirect(url_for('login_page'))
    if user.email_verified:
        flash("Email already verified. Please log in.", category='info')
        return redirect(url_for('login_page'))
    # Verify the email
    user.email_verified = True
    db.session.commit()
   
    session['show_welcome'] = True
    session['welcome_name'] = user.username
    # Create a notification for successful verification
    notification = Notification(
        user_id=user.id,
        content="Your email has been successfully verified!",
        read=False,
        created_at=datetime.utcnow()
    )
    db.session.add(notification)
    db.session.commit()
    # Log in the user after verification
    login_user(user)
    flash("Email verified successfully! Welcome aboard!", category='success')
    # Redirect based on role
    if user.role == 'admin':
        return redirect(url_for('create_event'))
    return redirect(url_for('new_home'))
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                if user.email_verified:
                    login_user(user)
                    session.permanent = True # Make session permanent
                    # Create login notification with "login" category
                    notification = Notification(
                        user_id=user.id,
                        content=f"Welcome back, {user.username}! You have successfully logged in.",
                        read=False,
                        created_at=datetime.utcnow(),
                        category="login" # Set category for styling in notifications.html
                    )
                    db.session.add(notification)
                    db.session.commit()
                    
                    session['show_welcome'] = True
                    session['welcome_name'] = user.username
                    
                    
                    # Redirect based on role
                    if user.role == 'admin':
                        return redirect(url_for('create_event'))
                    return redirect(url_for('new_home'))
                else:
                    flash("Please verify your email before logging in.", category='warning')
                    return redirect(url_for('verify_pending', email=user.email_address))
            else:
                flash("Incorrect password. Please try again.", category='danger')
                return render_template('login.html', form=form)
        else:
            flash("Username not found. Please register to create an account.", category='danger')
            return redirect(url_for('register_page'))
    
    return render_template('login.html', form=form)
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    form = ChatForm()
    user = current_user
   
    if user.role == 'farmer':
        form.receiver_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='vet').all()]
    else:
        form.receiver_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='farmer').all()]
   
    if form.validate_on_submit():
        message = Message(
            sender_id=user.id,
            receiver_id=form.receiver_id.data,
            content=form.content.data
        )
        db.session.add(message)
        notification = Notification(
            user_id=form.receiver_id.data,
            content=f"New message from {user.username}"
        )
        db.session.add(notification)
        receiver = User.query.get(form.receiver_id.data)
        send_vetconnect_alert(
            receiver.email_address,
            "New Message in VetApp",
            f"Hi {receiver.username},\n\nYou have a new message from {user.username}: {form.content.data}\n\nCheck it at {url_for('chat', _external=True)}"
        )
        db.session.commit()
        flash("Message sent!", category='success')
        return redirect(url_for('chat'))
   
    sent = Message.query.filter_by(sender_id=user.id).order_by(Message.timestamp.desc()).all()
    received = Message.query.filter_by(receiver_id=user.id).order_by(Message.timestamp.desc()).all()
   
    return render_template('chat.html', form=form, sent=sent, received=received)
@app.route('/tips', methods=['GET', 'POST'])
@login_required
def tips():
    form = TipForm()
    if current_user.role == 'vet' and form.validate_on_submit():
        try:
            tip = Tip(
                title=form.title.data,
                content=form.content.data,
                author_id=current_user.id
            )
            db.session.add(tip)
            db.session.commit()
           
            # Create notification for the vet (confirmation)
            vet_notification = Notification(
                content=f"Tip Posted: {form.title.data}",
                category='tip_confirmation',
                user_id=current_user.id
            )
            db.session.add(vet_notification)
            db.session.commit()
           
            flash("Tip posted successfully!", category='success')
            return redirect(url_for('tips'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error posting tip: {str(e)}", category='error')
            app.logger.error(f"Error saving tip: {str(e)}")
   
    tips_list = Tip.query.order_by(Tip.posted_at.desc()).all()
    return render_template('tips.html', form=form, tips_list=tips_list)
@app.route('/api/tips', methods=['GET'])
@login_required
def get_tips():
    try:
        tip = Tip.query.order_by(func.random()).first()
        if not tip:
            app.logger.info("No tips found, returning fallback")
            return jsonify({
                'title': 'Placeholder Tip',
                'content': 'Share your own livestock tips with the community!',
                'author': 'System',
                'posted_at': datetime.utcnow().strftime('%b %d, %Y %I:%M %p'),
                'type': 'tip'
            })
        return jsonify({
            'title': tip.title or 'Untitled Tip',
            'content': tip.content or 'No content',
            'author': tip.author.username if tip.author else 'Unknown',
            'posted_at': tip.posted_at.strftime('%b %d, %Y %I:%M %p') if tip.posted_at else 'Unknown',
            'type': 'tip'
        })
    except Exception as e:
        app.logger.error(f"Error fetching tip: {str(e)}")
        return jsonify({'error': 'Failed to load tip', 'message': str(e)}), 500
@app.route('/api/general_info', methods=['GET'])
@login_required
def get_general_info():
    try:
        # Verify table exists and has data
        item = GeneralInfo.query.order_by(func.random()).first()
        if not item:
            app.logger.info("No general info found, returning fallback")
            return jsonify({
                'title': 'Placeholder Health Tip',
                'content': 'Ensure regular vet checkups for livestock health.',
                'category': 'health',
                'created_at': datetime.utcnow().strftime('%b %d, %Y %I:%M %p'),
                'type': 'info'
            })
        # Ensure all fields are accessible
        return jsonify({
            'title': item.title if item.title else 'Untitled Info',
            'content': item.content if item.content else 'No content',
            'category': item.category if item.category else 'Unknown',
            'created_at': item.created_at.strftime('%b %d, %Y %I:%M %p') if item.created_at else 'Unknown',
            'type': 'info'
        })
    except Exception as e:
        app.logger.error(f"Error fetching general info: {str(e)}")
        # Ensure JSON response even on failure
        return jsonify({
            'error': 'Failed to load general info',
            'message': f"Server error: {str(e)}"
        }), 500
@app.route('/campaigns', methods=['GET', 'POST'])
def campaigns():
    form = CampaignForm()
    if current_user.role == 'vet' and form.validate_on_submit():
        campaign = Campaign(
            title=form.title.data,
            description=form.description.data,
            location=form.location.data,
            date=form.date.data,
            organizer=form.organizer.data
        )
        db.session.add(campaign)
        farmers = User.query.filter_by(role='farmer').all()
        for farmer in farmers:
            notification = Notification(
                user_id=farmer.id,
                content=f"New campaign: {form.title.data} in {form.location.data}"
            )
            db.session.add(notification)
            send_vetconnect_alert(
                farmer.email_address,
                "New Veterinary Campaign",
                f"Hi {farmer.username},\n\nA new campaign '{form.title.data}' is scheduled in {form.location.data} on {form.date.data.strftime('%Y-%m-%d %H:%M')}.\n\nDetails: {form.description.data}\n\nView at {url_for('campaigns', _external=True)}"
            )
        db.session.commit()
        flash("Campaign posted!", category='success')
        return redirect(url_for('campaigns'))
   
    campaigns_list = Campaign.query.order_by(Campaign.date.asc()).all()
    return render_template('campaigns.html', form=form, campaigns=campaigns_list)
@app.route('/notifications')
@login_required
def notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    else:
        notifications = Notification.query.filter_by(user_id=None).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)
@app.route('/notifications/count')
@login_required
def notifications_count():
    unread_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({'unread_count': unread_count})
@app.route('/mark_read/<int:id>', methods=['POST'])
@login_required
def mark_read(id):
    notification = Notification.query.get_or_404(id)
    if notification.user_id != current_user.id:
        flash("Unauthorized action.", category='danger')
        return redirect(url_for('notifications'))
    notification.read = True
    db.session.commit()
    flash("Notification marked as read.", category='success')
    return redirect(url_for('notifications'))
@app.route('/clear_notifications', methods=['POST'])
@login_required
def clear_notifications():
    deleted = Notification.query.filter_by(user_id=current_user.id, read=True).delete()
    db.session.commit()
    return redirect(url_for('notifications'))
@app.route('/logout')
@login_required
def logout_page():
    user_id = current_user.id
    logout_user()
    notification = Notification(user_id=user_id, content="You have been logged out.", read=False, category="platform")
    db.session.add(notification)
    db.session.commit()
    return redirect(url_for('notifications'))
#added this code for the search bar at the navbar in 'base.html'
@app.route('/search', methods=['GET'])
def search_results():
    query = request.args.get('animal', '').strip()
    if not query:
        return render_template('livestock_dashboard.html', error="Please enter an animal name.")
    conn = get_db_connection()
    cur = conn.cursor()
    # Get animal ID
    cur.execute("SELECT id FROM Animals WHERE LOWER(name) = LOWER(?)", (query,))
    animal = cur.fetchone()
    if not animal:
        conn.close()
        return render_template('livestock_dashboard.html', error=f"No data found for {query}.", animal=query)
    animal_id = animal['id']
    # Fetch static data (no age range)
    cur.execute("SELECT name AS species_name FROM Species WHERE animal_id = ?", (animal_id,))
    species = cur.fetchone()
    cur.execute("SELECT preferred_conditions AS habitat, temperature_range FROM Habitat WHERE animal_id = ?", (animal_id,))
    habitat = cur.fetchone()
    cur.execute("SELECT product_type AS produce FROM Produce WHERE animal_id = ?", (animal_id,))
    produce = cur.fetchone()
    # Fetch age-specific data
    cur.execute("SELECT age_range, feed_type, quantity_per_day FROM Feed WHERE animal_id = ?", (animal_id,))
    feeds = cur.fetchall()
    cur.execute("SELECT age_range, vaccine_name FROM VaccinationSchedule WHERE animal_id = ?", (animal_id,))
    vaccines = cur.fetchall()
    cur.execute("SELECT age_range, disease_name FROM Diseases WHERE animal_id = ?", (animal_id,))
    diseases = cur.fetchall()
    cur.execute("SELECT age_range, average_weight FROM WeightTracking WHERE animal_id = ?", (animal_id,))
    weights = cur.fetchall()
    cur.execute("SELECT age_range, supplement_name, dosage FROM AdditivesAndMinerals WHERE animal_id = ?", (animal_id,))
    supplements = cur.fetchall()
    conn.close()
    # Group age-specific data
    grouped_results = {}
    for table_data, key in [
        (feeds, 'feeds'), (vaccines, 'vaccines'), (diseases, 'diseases'),
        (weights, 'weights'), (supplements, 'supplements')
    ]:
        for row in table_data:
            age = row['age_range'] or 'Unknown'
            if age not in grouped_results:
                grouped_results[age] = {
                    'species_name': species['species_name'] if species else 'Not Available',
                    'habitat': habitat['habitat'] if habitat else 'Not Available',
                    'temperature_range': habitat['temperature_range'] if habitat else 'Not Available',
                    'produce': produce['produce'] if produce else 'Not Available',
                    'feeds': [], 'vaccines': [], 'diseases': [], 'weights': [], 'supplements': []
                }
            if key == 'feeds':
                grouped_results[age]['feeds'].append({'feed_type': row['feed_type'], 'quantity_per_day': row['quantity_per_day']})
            elif key == 'vaccines':
                grouped_results[age]['vaccines'].append(row['vaccine_name'])
            elif key == 'diseases':
                grouped_results[age]['diseases'].append(row['disease_name'])
            elif key == 'weights':
                grouped_results[age]['weights'].append(row['average_weight'])
            elif key == 'supplements':
                grouped_results[age]['supplements'].append({'supplement_name': row['supplement_name'], 'dosage': row['dosage']})
    if not grouped_results:
        return render_template('livestock_dashboard.html', error=f"No detailed data found for {query}.", animal=query)
    return render_template('livestock_dashboard.html', grouped_results=grouped_results, animal=query)
# Function to connect to SQLite
def get_db_connection():
    conn = sqlite3.connect('C:/Users/ADMIN/.vscode/.vscode/FlaskMarket/market.db')
    conn.row_factory = sqlite3.Row # Allows fetching results as dictionaries
    return conn
# Age Calculator Route
@app.route('/livestock_dashboard/age_calculator', methods=['POST'])
def age_calculator():
    try:
        # Get form data
        dob_str = request.form['dob']
        calc_date_str = request.form['calc_date']
        format_choice = request.form['format_choice']
        # Convert strings to datetime objects
        dob = datetime.strptime(dob_str, '%Y-%m-%d')
        calc_date = datetime.strptime(calc_date_str, '%Y-%m-%d')
        # Validate dates
        if calc_date < dob:
            return jsonify({"error": "Calculate date must be after date of birth."})
        # Use relativedelta for precise age calculation
        delta = relativedelta(calc_date, dob)
        # Format result based on choice
        if format_choice == 'days':
            total_days = (calc_date - dob).days
            result = f"{total_days} days"
        elif format_choice == 'weeks':
            total_days = (calc_date - dob).days
            weeks = total_days // 7
            result = f"{weeks} weeks"
        elif format_choice == 'months':
            months = delta.years * 12 + delta.months
            result = f"{months} months"
        elif format_choice == 'years':
            years = delta.years
            result = f"{years} years"
        elif format_choice == 'ymd':
            result = f"{delta.years} years, {delta.months} months, {delta.days} days"
        return jsonify({"result": result})
    except ValueError:
        return jsonify({"error": "Invalid date format. Please use YYYY-MM-DD."})
def get_animal_info(animal_name):
    conn = sqlite3.connect('C:/Users/ADMIN/.vscode/.vscode/FlaskMarket/market.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM animals WHERE LOWER(name) = LOWER(?)", (animal_name,))
    animal = cursor.fetchone()
    conn.close()
    return animal
@app.route('/Privacy_page')
def Privacy_page():
    return render_template('Privacy_page.html')
@app.route('/nearby_vets')
def nearby_vets():
    return render_template('nearby-vets.html')
@app.route('/nearby-vets-2')
def nearby_vets_2():
    return render_template('nearby-vets-2.html')
@app.route('/nearby-vets-3')
def nearby_vets_3():
    return render_template('nearby-vets-3.html')
@app.route('/nearby_vets_4')
@login_required
def nearby_vets_4():
    page = request.args.get('page', 1, type=int) # Pagination support
    vets = Vet.query.paginate(page=page, per_page=10) # Adjust per_page as needed
    return render_template('nearby-vets-4.html', vets=vets)
@app.route('/schedule_appointment', methods=['POST'])
def schedule_appointment():
    vet_id = request.form.get('vet_id')
    appointment_date = request.form.get('appointmentDate')
    appointment_time = request.form.get('appointmentTime')
    animal_type = request.form.get('animalType')
    owner_name = request.form.get('ownerName')
    owner_email = request.form.get('ownerEmail')
    vet = Veterinary.query.get(vet_id)
    if vet:
        flash(f"Appointment booked with {vet.name} on {appointment_date} at {appointment_time} for your {animal_type}!", category='success')
    else:
        flash("Error booking appointment. Vet not found.", category='danger')
   
    return redirect(url_for('nearby_vets'))
@app.route('/home2_page')
def home2_page():
    return render_template('home2.html')
@app.route('/livestock_dashboard')
def livestock_dashboard():
    return render_template('livestock_dashboard.html')
@app.route('/connect-farmers')
def connect_farmers():
    farmers = Farmer.query.all()
    return render_template('connect-farmers.html', farmers=farmers)
@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    try:
        data = request.get_json()
        vet_id = data.get('vetId')
        vet_name = data.get('vetName')
        appointment_date = data.get('appointmentDate')
        appointment_time = data.get('appointmentTime')
        animal_type = data.get('animalType')
        owner_name = data.get('ownerName')
        owner_email = data.get('ownerEmail')
        # Validate required fields
        if not all([vet_id, vet_name, appointment_date, appointment_time, animal_type, owner_name, owner_email]):
            return jsonify({'error': 'Missing required fields'}), 400
        # Save the appointment
        appointment = Appointment(
            vet_id=int(vet_id),
            vet_name=vet_name,
            appointment_date=appointment_date,
            appointment_time=appointment_time,
            animal_type=animal_type,
            owner_name=owner_name,
            owner_email=owner_email,
            user_id=current_user.id
        )
        db.session.add(appointment)
        # Create a notification for the user
        notification = Notification(
            content=f"Appointment booked with {vet_name} on {appointment_date} at {appointment_time} for your {animal_type}",
            category='appointment',
            user_id=current_user.id
        )
        db.session.add(notification)
        db.session.commit()
        # Send confirmation email
        send_appointment_email(owner_email, vet_name, appointment_date, appointment_time, animal_type, owner_name)
        return jsonify({'message': 'Appointment booked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error booking appointment: {str(e)}")
        return jsonify({'error': str(e)}), 500
   
def send_vet_confirmation_email(email_receiver, vet_name):
    subject = 'Vet Profile Added - Livestock Management System'
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                text-align: center;
                padding: 20px 0;
                background-color: #D2B48C;
                color: white;
                border-radius: 8px 8px 0 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 20px;
                color: #333;
            }}
            .content p {{
                line-height: 1.6;
                margin: 10px 0;
            }}
            .footer {{
                text-align: center;
                padding: 10px;
                font-size: 12px;
                color: #777;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://livestockanalytics.com/hs-fs/hubfs/Logos%20e%20%C3%ADconos/livestock.png?width=115&height=70&name=livestock.png" alt="Livestock Management" style="max-width: 150px;">
                <h1>Livestock Management System</h1>
            </div>
            <div class="content">
                <p>Hello {vet_name},</p>
                <p>Your vet profile has been successfully added to the Livestock Management System!</p>
                <p>You can now be discovered by farmers and pet owners looking for veterinary services. Log in to manage your profile and appointments.</p>
            </div>
            <div class="footer">
                <p>© 2025 Livestock Management System. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
   
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body, subtype='html')
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, EMAIL_PASSWORD)
            smtp.sendmail(email_sender, email_receiver, em.as_string())
        app.logger.info(f"Vet confirmation email sent to {email_receiver}")
    except Exception as e:
        app.logger.error(f"Email error: {str(e)}")
        raise
   
   
@app.route('/add_vet', methods=['GET', 'POST'])
@login_required
def add_vet():
    if current_user.role != 'vet':
        flash('Only vets can add profiles.', 'error')
        return redirect(url_for('nearby_vets_4'))
   
    form = VetForm()
    if form.validate_on_submit():
        vet_id = f"vet_{current_user.id}_{uuid4().hex[:8]}"
        while Vet.query.filter_by(vet_id=vet_id).first():
            vet_id = f"vet_{current_user.id}_{uuid4().hex[:8]}"
        # Compute the rating string
        rating_score = form.rating_score.data
        review_count = form.review_count.data
        rating = f"{rating_score} ({review_count} reviews)"
        vet = Vet(
            vet_id=vet_id,
            user_id=current_user.id,
            name=form.name.data,
            specialty=form.specialty.data,
            clinic=form.clinic.data,
            experience=int(form.experience.data),
            availability=form.availability.data,
            accepting=form.accepting.data,
            rating=rating, # Store computed rating
            rating_score=rating_score,
            review_count=review_count,
            price=0,
            image_url=form.image_url.data or "https://via.placeholder.com/300x150",
            reviews=form.reviews.data or ""
        )
        db.session.add(vet)
        db.session.commit()
        vet_notification = Notification(
            content=f"Vet profile added: {vet.name}",
            category='vet_added',
            user_id=current_user.id
        )
        db.session.add(vet_notification)
        other_users = User.query.filter(User.id != current_user.id).all()
        for user in other_users:
            user_notification = Notification(
                content=f"New vet added: {vet.name}",
                category='new_vet',
                user_id=user.id
            )
            db.session.add(user_notification)
            try:
                send_vet_confirmation_email(user.email, vet.name, user.username)
            except Exception as e:
                app.logger.error(f"Failed to send new vet notification to {user.email}: {str(e)}")
        db.session.commit()
        try:
            send_vet_confirmation_email(form.email.data, vet.name)
        except Exception as e:
            app.logger.error(f"Failed to send vet confirmation email to {form.email.data}: {str(e)}")
            flash('Vet profile added successfully, but failed to send confirmation email.', 'warning')
        else:
            flash('Vet profile added successfully! A confirmation email has been sent.', 'success')
        return redirect(url_for('nearby_vets'))
   
    return render_template('add_vet.html', form=form)
   
   
   
@app.route('/edit_vet/<vet_id>', methods=['GET', 'POST'])
@login_required
def edit_vet(vet_id):
    vet = Vet.query.filter_by(vet_id=vet_id, user_id=current_user.id).first()
    if not vet:
        flash('Vet profile not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('vet_dashboard'))
    form = VetForm(obj=vet)
    if form.validate_on_submit():
        vet.name = form.name.data
        vet.specialty = form.specialty.data
        vet.clinic = form.clinic.data
        vet.experience = int(form.experience.data)
        vet.availability = form.availability.data
        vet.accepting = form.accepting.data
        vet.rating_score = form.rating_score.data
        vet.review_count = form.review_count.data
        vet.rating = f"{form.rating_score.data} ({form.review_count.data} reviews)" # Update rating string
        vet.image_url = form.image_url.data or "https://via.placeholder.com/300x150"
        vet.reviews = form.reviews.data or ""
        db.session.commit()
        flash('Vet profile updated successfully!', 'success')
        return redirect(url_for('list_vets'))
    return render_template('edit_vet.html', form=form, vet=vet)
   
   
   
@app.route('/list_vets', defaults={'page': 1})
@app.route('/list_vets/<int:page>')
def list_vets(page):
    per_page = 6
    vets = Vet.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('nearby-vets-4.html', vets=vets, current_user=current_user)
# Define synonyms for animal types
ANIMAL_SYNONYMS = {
    'cow': ['cow', 'cattle', 'calf', 'bovine'],
    'cattle': ['cow', 'cattle', 'calf', 'bovine'],
    'calf': ['cow', 'cattle', 'calf', 'bovine'],
    'bovine': ['cow', 'cattle', 'calf', 'bovine'],
    'goat': ['goat', 'kid'],
    'sheep': ['sheep', 'lamb', 'ewe'],
    'pig': ['pig', 'swine', 'hog', 'boar', 'sow'],
    'swine': ['pig', 'swine', 'hog', 'boar', 'sow'],
    'chicken': ['chicken', 'poultry', 'hen', 'rooster'],
    'poultry': ['chicken', 'poultry', 'hen', 'rooster'],
    'horse': ['horse', 'mare', 'stallion', 'foal'],
    'donkey': ['donkey', 'ass', 'mule'],
    'cat': ['cat', 'kitten', 'feline'],
    'dog': ['dog', 'puppy', 'canine'],
    'rabbit': ['rabbit', 'bunny'],
    'camel': ['camel', 'dromedary', 'bactrian']
}
# Predefined symptom synonyms (from previous implementation)
SYMPTOM_SYNONYMS = {
    "high temperature": "fever",
    "elevated temperature": "fever",
    "coughing": "cough",
    "runny nose": "nasal discharge",
    "sneezing": "nasal discharge",
    "tiredness": "lethargy",
    "weakness": "lethargy",
    "breathing difficulty": "respiratory distress",
    "lameness": "limping",
    "rapid breathing": "respiratory distress",
    "weight loss": "emaciation",
    "swollen udder": "painful udder",
    "milk clots": "reduced milk yield",
    "redness of udder": "painful udder"
}
@app.route('/search_symptoms', methods=['POST'])
def search_symptoms():
    try:
        # Parse input
        data = request.get_json()
        animal_name = data.get('animal_name', '').strip().lower()
        raw_symptoms = data.get('symptoms', '').strip().lower().split(',')[:7]
        symptoms = []
        for symptom in raw_symptoms:
            sub_symptoms = [s.strip() for s in symptom.replace(' and ', ',').split(',')]
            symptoms.extend(sub_symptoms)
        symptoms = [s for s in symptoms if s]
        if not animal_name or not symptoms:
            return jsonify({'error': 'Please provide both animal name and symptoms.'}), 400
        print(f"Input - Animal: {animal_name}, Symptoms: {symptoms}")
        # Normalize animal name using synonyms
        animal_synonyms = []
        for key, synonyms in ANIMAL_SYNONYMS.items():
            if animal_name in synonyms:
                animal_synonyms.extend(synonyms)
                animal_name = key # Standardize to the key (e.g., "cow" -> "cattle")
                break
        if not animal_synonyms:
            animal_synonyms = [animal_name]
        print(f"Animal synonyms: {animal_synonyms}")
        # Normalize symptoms using synonyms
        normalized_symptoms = []
        for symptom in symptoms:
            normalized_symptom = SYMPTOM_SYNONYMS.get(symptom, symptom)
            normalized_symptoms.append(normalized_symptom)
        print(f"Normalized symptoms: {normalized_symptoms}")
        # Fetch diseases from the database
        diseases = SymptomCheckerDisease.query.all()
        print(f"Total diseases queried: {len(diseases)}")
        # Match diseases based on animal type and symptoms
        matching_diseases = []
        for disease in diseases:
            print(f"Checking disease: {disease.name}, Animal Type: {disease.animal_type}, Symptoms: {disease.symptoms}")
           
            # Check if any synonym matches the animal type
            animal_type_lower = disease.animal_type.lower()
            if any(synonym in animal_type_lower for synonym in animal_synonyms):
                print(f"Animal match: {animal_name} (via {animal_synonyms}) found in {animal_type_lower}")
               
                # Parse disease symptoms
                disease_symptoms = [s.strip().lower() for s in disease.symptoms.split(',')]
                if not disease_symptoms:
                    print(f"No symptoms found for disease: {disease.name}")
                    continue
                # Simple string-based matching for symptoms
                matching_symptom_count = 0
                matched_symptoms = set()
                for input_symptom in normalized_symptoms:
                    for db_symptom in disease_symptoms:
                        if input_symptom in db_symptom or db_symptom in input_symptom:
                            matching_symptom_count += 1
                            matched_symptoms.add(input_symptom)
                            print(f"Symptom match: {input_symptom} matches {db_symptom}")
                            break
               
                if matching_symptom_count > 0:
                    matching_diseases.append({
                        'name': disease.name,
                        'animal_type': disease.animal_type,
                        'matching_symptoms': matching_symptom_count,
                        'action_to_take': disease.action_to_take # Include action_to_take
                    })
                    print(f"Added disease: {disease.name} with {matching_symptom_count} matching symptoms")
        # Sort by number of matching symptoms and limit to top 3
        matching_diseases.sort(key=lambda x: x['matching_symptoms'], reverse=True)
        matching_diseases = matching_diseases[:3]
        print(f"Matching diseases: {matching_diseases}")
        if not matching_diseases:
            return jsonify({'error': 'No matching diseases found for the given symptoms.'}), 404
        return jsonify({'diseases': matching_diseases})
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500
   
   
   
@app.route('/search_vets', methods=['POST'])
def search_vets():
    data = request.get_json()
    vet_name = data.get('vetName', '').lower()
    specialty = data.get('specialty', '').lower()
    clinic = data.get('clinic', '').lower()
    animal_type = data.get('animalType', '').lower()
    # Build the query
    query = Vet.query
    # Filter by vet name
    if vet_name:
        query = query.filter(Vet.name.ilike(f'%{vet_name}%'))
    # Filter by specialty (disease expertise)
    if specialty:
        # Remove common suffixes like "expert" or "specialist" for broader matching
        specialty_keywords = [specialty]
        for suffix in ['expert', 'specialist']:
            if specialty.endswith(suffix):
                specialty_keywords.append(specialty.replace(suffix, '').strip())
        # Search for any of the keywords in the specialty field
        specialty_conditions = [Vet.specialty.ilike(f'%{keyword}%') for keyword in specialty_keywords]
        query = query.filter(or_(*specialty_conditions))
    # Filter by clinic (locality)
    if clinic:
        query = query.filter(Vet.clinic.ilike(f'%{clinic}%'))
    # Filter by animal type (specific animal or category)
    if animal_type:
        # Map animals to categories and keywords
        animal_category_map = {
            'dog': ['dog', 'small animals', 'mammal'],
            'cat': ['cat', 'small animals', 'mammal'],
            'cow': ['cow', 'large animals', 'mammal'],
            'horse': ['horse', 'large animals', 'mammal'],
            'pig': ['pig', 'large animals', 'mammal'],
            'goat': ['goat', 'large animals', 'mammal'],
            'sheep': ['sheep', 'large animals', 'mammal'],
            'parrot': ['parrot', 'avian', 'bird'],
            'chicken': ['chicken', 'avian', 'bird'],
            'rabbit': ['rabbit', 'small animals', 'mammal'],
            'hamster': ['hamster', 'small animals', 'mammal']
        }
        # Get the list of keywords to search for in specialty
        search_keywords = animal_category_map.get(animal_type, [animal_type])
        animal_conditions = [Vet.specialty.ilike(f'%{keyword}%') for keyword in search_keywords]
        query = query.filter(or_(*animal_conditions))
    vets = query.all()
    # Convert vets to a JSON-serializable format
    vet_list = [{
        'id': vet.id,
        'name': vet.name,
        'specialty': vet.specialty,
        'clinic': vet.clinic,
        'experience': vet.experience,
        'availability': vet.availability,
        'accepting': vet.accepting,
        'rating': vet.rating,
        'price': vet.price,
        'image_url': vet.image_url
    } for vet in vets]
    return jsonify({'vets': vet_list})
@app.route('/admin/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if current_user.role != 'admin':
        flash('Unauthorized access. Only admins can create events.', 'error')
        return redirect(url_for('home_page'))
   
    form = CreateEventForm()
    if form.validate_on_submit():
        event_date = datetime.combine(form.event_date.data, time(0, 0))
        new_event = Event(
            title=form.title.data,
            content=form.content.data,
            event_date=event_date
        )
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('home_page'))
   
    return render_template('create_event.html', form=form)
@app.route('/unsubscribe/<email>')
def unsubscribe(email):
    user = User.query.filter_by(email_address=email).first()
    if user and user.role == 'subscriber':
        db.session.delete(user)
        db.session.commit()
        flash('You have been unsubscribed successfully.', 'success')
    else:
        flash('Email not found or not a subscriber.', 'error')
    return redirect(url_for('home_page'))
@app.route('/analytics_dashboard')
def analytics_dashboard():
    return render_template('analytics_dashboard.html')
@app.route('/animal_search_results', methods=['GET'])
def animal_search_results():
    query = request.args.get('animal', '').strip()
    if not query:
        return render_template('analytics_dashboard.html', error="Please enter an animal name.")
    animal = Animalia.query.filter(db.func.lower(Animalia.name) == query.lower()).first()
    if not animal:
        return render_template('analytics_dashboard.html', error=f"No data found for {query}.", animal=query)
    animal_id = animal.id
    species = Specificia.query.filter_by(animal_id=animal_id).first()
    habitat = Habitatty.query.filter_by(animal_id=animal_id).first()
    feeds = AnimalsFeed.query.filter_by(animal_id=animal_id).all()
    vaccines = VaccinationTimetable.query.filter_by(animal_id=animal_id).all()
    diseases = DiseasesInfection.query.filter_by(animal_id=animal_id).all()
    feed_intakes = ExpectedFeedIntake.query.filter_by(animal_id=animal_id).all()
    produces = ExpectedProduce.query.filter_by(animal_id=animal_id).all()
    feeds_chart_data = [
        {"age_range": f.age_range, "feed_type": f.feed_type, "quantity_per_day": f.quantity_per_day}
        for f in feeds
    ]
    vaccination_chart_data = [
        {"age_range": v.age_range, "vaccine_name": v.vaccine_name}
        for v in vaccines
    ]
    diseases_infection_chart_data = [
        {"age_range": d.age_range, "disease_name": d.disease_name}
        for d in diseases
    ]
    feed_intake_chart_data = [
        {"age_range": fi.age_range, "expected_intake": fi.expected_intake}
        for fi in feed_intakes
    ]
    produce_chart_data = [
        {"age_range": p.age_range, "product_type": p.product_type, "expected_amount": p.expected_amount}
        for p in produces
    ]
    grouped_results = {}
    for table_data, key in [
        (feeds, 'feeds'), (vaccines, 'vaccines'),
        (diseases, 'diseases_infection'),
        (feed_intakes, 'feed_intakes'), (produces, 'produces')
    ]:
        for row in table_data:
            age = row.age_range or 'Unknown'
            if age not in grouped_results:
                grouped_results[age] = {
                    'species_name': species.name if species else 'Not Available',
                    'habitat': habitat.preferred_conditions if habitat else 'Not Available',
                    'temperature_range': habitat.temperature_range if habitat else 'Not Available',
                    'feeds': [], 'vaccines': [],
                    'diseases_infection': [],
                    'feed_intakes': [], 'produces': []
                }
            if key == 'feeds':
                grouped_results[age]['feeds'].append({'feed_type': row.feed_type, 'quantity_per_day': row.quantity_per_day})
            elif key == 'vaccines':
                grouped_results[age]['vaccines'].append(row.vaccine_name)
            elif key == 'diseases_infection':
                grouped_results[age]['diseases_infection'].append(row.disease_name)
            elif key == 'feed_intakes':
                grouped_results[age]['feed_intakes'].append(row.expected_intake)
            elif key == 'produces':
                grouped_results[age]['produces'].append({'product_type': row.product_type, 'expected_amount': row.expected_amount})
    if not grouped_results:
        return render_template('analytics_dashboard.html', error=f"No detailed data found for {query}.", animal=query)
    return render_template(
        'analytics_dashboard.html',
        grouped_results=grouped_results,
        animal=query,
        feeds_chart_data=feeds_chart_data,
        vaccination_chart_data=vaccination_chart_data,
        diseases_chart_data=diseases_infection_chart_data,
        feed_intake_chart_data=feed_intake_chart_data,
        produce_chart_data=produce_chart_data
    )
   
   
@app.route('/dashboard')
def dashboard():
    # Fetch all animals
    animals = Animalia.query.all()
    total_feed_intake_data = []
    total_produce_data = []
    for animal in animals:
        animal_id = animal.id
        # Aggregate feed intake
        feed_intakes = ExpectedFeedIntake.query.filter_by(animal_id=animal_id).all()
        total_feed = sum(fi.expected_intake for fi in feed_intakes)
        total_feed_intake_data.append({"animal": animal.name, "total_feed": total_feed})
        # Aggregate produce
        produces = ExpectedProduce.query.filter_by(animal_id=animal_id).all()
        total_produce = sum(p.expected_amount for p in produces)
        total_produce_data.append({"animal": animal.name, "total_produce": total_produce})
    return render_template(
        'dashboard.html',
        total_feed_intake_data=total_feed_intake_data,
        total_produce_data=total_produce_data
    )
   
   
@app.route('/api/chart_data/<animal>/<chart_type>/<age_range>', methods=['GET'])
def get_chart_data(animal, chart_type, age_range):
    animal = Animalia.query.filter(db.func.lower(Animalia.name) == animal.lower()).first()
    if not animal:
        return {"error": "Animal not found"}, 404
    animal_id = animal.id
    if chart_type == "feeds":
        data = AnimalsFeed.query.filter_by(animal_id=animal_id, age_range=age_range).all()
        chart_data = [{"age_range": d.age_range, "feed_type": d.feed_type, "quantity_per_day": d.quantity_per_day} for d in data]
    elif chart_type == "vaccines":
        data = VaccinationTimetable.query.filter_by(animal_id=animal_id, age_range=age_range).all()
        chart_data = [{"age_range": d.age_range, "vaccine_name": d.vaccine_name} for d in data]
    elif chart_type == "diseases":
        data = DiseasesInfection.query.filter_by(animal_id=animal_id, age_range=age_range).all()
        chart_data = [{"age_range": d.age_range, "disease_name": d.disease_name} for d in data]
    elif chart_type == "feed_intake":
        data = ExpectedFeedIntake.query.filter_by(animal_id=animal_id, age_range=age_range).all()
        chart_data = [{"age_range": d.age_range, "expected_intake": d.expected_intake} for d in data]
    elif chart_type == "produce":
        data = ExpectedProduce.query.filter_by(animal_id=animal_id, age_range=age_range).all()
        chart_data = [{"age_range": d.age_range, "product_type": d.product_type, "expected_amount": d.expected_amount} for d in data]
    else:
        return {"error": "Invalid chart type"}, 400
    return chart_data
@app.route('/create_livestock_event', methods=['GET', 'POST'])
@login_required
def create_livestock_event():
    if current_user.role != 'admin':
        flash('Unauthorized access. Only admins can create events.', 'error')
        return redirect(url_for('home_page'))
    if request.method == 'POST':
        title = request.form['event_title']
        description = request.form['event_description']
        date = request.form['event_date']
        time = request.form['event_time']
        duration = int(request.form['event_duration'])
        image_url = request.form.get('event_image', '')
        # Create a new event
        new_event = Event(
            title=title,
            content=description, # Map to your existing 'content' field
            event_date=datetime.strptime(date, '%Y-%m-%d'),
            time=time, # Add this to your Event model if not already present
            duration=duration, # Add this to your Event model if not already present
            image_url=image_url if image_url else None # Add this to your Event model if not already present
        )
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('home_page'))
    return render_template('create-event.html')


@app.route('/home-design')
def home_design():
    return render_template('home-design.html')

@app.route('/vaccination-design')
def vaccination_design():
    return render_template('vaccination_design.html')

@app.route('/NewHome')
def new_home():
    return render_template('New_home.html')

@app.route('/NewVaccinationSchedule')
def new_vaccination_schedule():
    return render_template('NewVaccinationSchedule.html')

@app.route('/NewHealthMatters')
def new_health_matters():
    return render_template('NewHealthMatters.html')

@app.route('/NewFeedsAdditives')
def new_feeds_additives():
    return render_template('NewFeedsAdditives.html')

@app.route('/NewGrowthMonitor')
def new_growth_monitor():
    return render_template('NewGrowthMonitor.html')

@app.route('/NewHabitatManagement')
def new_habitat_management():
    return render_template('NewHabitatManagement.html')

@app.route('/NewSpeciesVariety')
def new_species_variety():
    return render_template('NewSpeciesVariety.html')

@app.route('/NewVetAppointment')
def new_vet_appointment():
    return render_template('NewVetAppointment.html')

@app.route('/NewFarmersCommunity')
def new_farmers_community():
    return render_template('NewFarmersCommunity.html')

@app.route('/NewSymptomChecker')
def new_symptom_checker():
    return render_template('NewSymptomChecker.html')

@app.route('/api/vaccination')
def api_vaccination():
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Join: Animals → VaccinationSchedule → animalia/specificia (for species)
    cur.execute("""
        SELECT
            a.id AS animal_id,
            a.name AS animal_name,
            vs.vaccine_name,
            vs.age_bracket,
            vs.date_given,
            vs.next_due,
            ani.name AS species,
            COALESCE(
                (julianday(vs.next_due) - julianday(date('now'))), 999
            ) AS days_until_due,
            -- Optional tag from another table if you have it
            NULL AS tag
        FROM Animals a
        LEFT JOIN VaccinationSchedule vs ON vs.animal_id = a.id
        LEFT JOIN animalia ani ON ani.id = a.id
        LEFT JOIN specificia spec ON spec.animal_id = ani.id
        WHERE vs.next_due IS NOT NULL
        ORDER BY days_until_due ASC
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        avatar_url = request.form.get('avatar_url', '')  # From form input
        if avatar_url:
            current_user.avatar_url = avatar_url
            db.session.commit()
            flash('Avatar updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

# NEW: Settings Route (placeholder for preferences)
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)