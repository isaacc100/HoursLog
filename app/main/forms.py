from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, FloatField, DateField, SelectField, SelectMultipleField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, EqualTo
from datetime import date


class LogEntryForm(FlaskForm):
    """Form for creating/editing log entries."""
    title = StringField('Title', validators=[DataRequired(), Length(min=3, max=200)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    notes = TextAreaField('Notes', validators=[Length(max=1000)])
    hours = FloatField('Activity Hours', validators=[DataRequired(), NumberRange(min=0.1, max=24)])
    travel_hours = FloatField('Travel Hours', validators=[Optional(), NumberRange(min=0, max=24)], default=0.0)
    date = DateField('Date', validators=[DataRequired()], default=date.today)
    category_id = SelectField('Category', validators=[DataRequired()], coerce=int)
    role_id = SelectField('Primary Role', validators=[DataRequired()], coerce=int)
    secondary_role_ids = SelectMultipleField('Secondary Roles (optional)', coerce=int, validators=[Optional()])
    submit = SubmitField('Save Entry')


class ProfileForm(FlaskForm):
    """Form for editing user profile."""
    display_name = StringField('Display Name', validators=[Optional(), Length(max=100)])
    profile_pic = FileField('Profile Picture', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'webp'], 'Images only!')
    ])
    submit = SubmitField('Save Changes')


class ChangePasswordForm(FlaskForm):
    """Form for changing user password."""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), EqualTo('new_password', message='Passwords must match.')
    ])
    submit_password = SubmitField('Change Password')


class CategoryForm(FlaskForm):
    """Form for creating/editing categories."""
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    description = StringField('Description', validators=[Length(max=200)])
    color = StringField('Color', validators=[DataRequired(), Length(min=7, max=7)], default='#007bff')
    submit = SubmitField('Save Category')


class RoleForm(FlaskForm):
    """Form for creating/editing roles."""
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    description = StringField('Description', validators=[Length(max=200)])
    submit = SubmitField('Save Role')
