
from flask_wtf import FlaskForm

from wtforms.fields import DateField, TimeField

from wtforms import DateField, IntegerField, FloatField, SelectField, StringField, PasswordField, SubmitField, TextAreaField, SelectField, DateTimeField
from wtforms.validators import NumberRange, Length, EqualTo, Email, DataRequired, ValidationError
from market.models import User




class LoginForm(FlaskForm):
    username = StringField('User Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')
    
class PurchaseItemForm(FlaskForm):
    submit = SubmitField(label='Purchase Item!')

class SellItemForm(FlaskForm):
    submit = SubmitField(label='Sell Item!')
    
    
class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')

    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=30)])
    email_address = StringField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    password1 = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password1')])
    role = SelectField('Role', choices=[('farmer', 'Farmer'), ('vet', 'Vet'), ('normal_user', 'Normal User'), ('admin', 'Admin')], validators=[DataRequired()], default='normal_user')
    submit = SubmitField('Register')

    # Optional: Add validation to ensure role is one of the allowed choices
    def validate_role(self, role_to_check):
        if role_to_check.data not in [choice[0] for choice in self.role.choices]:
            raise ValidationError('Invalid role selected!')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=30)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChatForm(FlaskForm):
    receiver_id = SelectField('Send To', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Send')

class CampaignForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=1000)])
    location = StringField('Location', validators=[DataRequired(), Length(max=100)])
    date = DateTimeField('Date', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    organizer = StringField('Organizer', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Post Campaign')

class TipForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Post Tip')


class GeneralInfoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=1000)])
    category = SelectField('Category', choices=[
        ('health', 'Health'),
        ('feeding', 'Feeding'),
        ('medication', 'Medication'),
        ('care', 'Care')
    ], validators=[DataRequired()])
    submit = SubmitField('Post Info')
    

    
class VetForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    specialty = StringField('Specialty', validators=[DataRequired()])
    clinic = StringField('Clinic', validators=[DataRequired()])
    experience = IntegerField('Experience (Years)', validators=[DataRequired()])
    availability = StringField('Availability', validators=[DataRequired()])
    accepting = StringField('Accepting', validators=[DataRequired()])
    image_url = StringField('Image URL')
    rating_score = SelectField('Rating Score (0-5)', choices=[(0.0, '0'), (1.0, '1'), (2.0, '2'), (3.0, '3'), (4.0, '4'), (5.0, '5')], coerce=float, default=0.0)
    review_count = IntegerField('Number of Reviews', default=0)
    reviews = StringField('Reviews (Optional)', render_kw={"placeholder": "e.g., Highly recommended! Great with small animals."})
    submit = SubmitField('Submit')
    
    
    
class CreateEventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired()])
    content = TextAreaField('Event Details', validators=[DataRequired()])
    event_date = DateField('Event Date (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired()])
    start_time = TimeField('Start Time', format='%H:%M', validators=[DataRequired()])
    end_time = TimeField('End Time', format='%H:%M', validators=[DataRequired()])
    submit = SubmitField('Create Event')
    
# NEW CODE ADDED: Add Animal Form
class AddAnimalForm(FlaskForm):
    name = StringField('Animal Name', validators=[DataRequired()])
    submit = SubmitField('Add Animal')

# NEW CODE ADDED: Add Vaccine Form
class AddVaccineForm(FlaskForm):
    animal_id = SelectField('Animal', coerce=int, validators=[DataRequired()])
    vaccine_name = StringField('Vaccine Name', validators=[DataRequired()])
    age_bracket = StringField('Age Bracket', validators=[DataRequired()])
    next_due = DateField('Next Due Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Add Vaccine')