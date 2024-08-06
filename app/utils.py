from flask_mail import Message
from flask import current_app
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from datetime import timedelta

def send_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    msg.sender = current_app.config['MAIL_USERNAME']
    mail.send(msg)

def generate_token(user):
    expires = timedelta(days=7)
    user_claims = {'role': user.role}
    access_token = create_access_token(
        identity=user.id,
        additional_claims=user_claims,
        expires_delta=expires
    )
    return access_token
