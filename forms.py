from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User
from wtforms.fields import DateField
from wtforms import StringField


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 128)])
    confirm = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')



class GroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired(), Length(3, 100)])
    description = StringField('Description')
    submit = SubmitField('Create Group')


class AddMemberForm(FlaskForm):
    user_id = SelectField('Select User', coerce=int, validators=[DataRequired()])
    role = SelectField(
    'Assign Role',
    choices=[
        ('backend', 'Backend Developer'),
        ('frontend', 'Frontend Developer'),
        ('designer', 'Designer'),
        ('qa', 'QA Engineer'),
        ('ml', 'ML Engineer'),
        ('lead', 'Project Lead'),
        ('member', 'General Member'),
        ('admin', 'Admin')
    ],
    validators=[DataRequired()]
)
    submit = SubmitField('Add Member')

class TaskForm(FlaskForm):
    title = StringField('Task Title', validators=[DataRequired(), Length(3, 150)])
    description = StringField('Description')
    due_date = DateField('Due Date (optional)', format='%Y-%m-%d', validators=[], default=None)
    assigned_to = SelectField('Assign To (Admin Only)', coerce=int, choices=[])
    submit = SubmitField('Create Task')
    tags = StringField('Tags (comma-separated)', description='Optional tags, e.g. bug,backend')


    priority = SelectField(
    'Priority',
    choices=[('high', 'High'), ('low', 'Low')],
    default='low',
    validators=[DataRequired()]
    )



class MessageForm(FlaskForm):
    message = StringField('Type your message', validators=[DataRequired(), Length(1, 500)])
    submit = SubmitField('Send')


class TaskUpdateForm(FlaskForm):

  
    status = SelectField('Status', choices=[
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Done', 'Done')
    ])


    priority = SelectField(
    'Priority',
    choices=[
        ('high', 'High'),
        ('low', 'Low')
    ],
    validators=[DataRequired()]
    )

    comment = StringField('Add your remark', validators=[DataRequired(), Length(1, 300)])
    submit = SubmitField('Update Task')