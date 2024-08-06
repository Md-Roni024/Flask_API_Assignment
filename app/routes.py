from flask import Blueprint, request, url_for,jsonify,render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User
from .schemas import UserSchema, UserRegistrationSchema, UserLoginSchema,UpdateUserSchema
from .utils import generate_token,send_email
from config import Config
from marshmallow import ValidationError
import secrets
from datetime import timedelta
from flask_swagger_ui import get_swaggerui_blueprint



userBlueprint = Blueprint("user", __name__, url_prefix="/")
user_schema = UserSchema()
user_registration_schema = UserRegistrationSchema()
user_login_schema = UserLoginSchema()



#Route-1: Home Route or Root Route
# @userBlueprint.route("/",methods=['GET'])
# def home():
#     return "Home Route"

@userBlueprint.route('/')
def swagger():
    return render_template('swagger-ui.html')


#Route-2: User Registration Route
@userBlueprint.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    print("data:", data)
    try:
        user_data = user_registration_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": err.messages}), 400

    if User.query.filter_by(username=user_data['username']).first():
        return jsonify({"error": "Username already exists"}), 400
    if User.query.filter_by(email=user_data['email']).first():
        return jsonify({"error": "Email already exists"}), 400

    # Directly use the role from user input
    role = user_data.get('role', 'User')  # Default to 'User' if not provided

    user = User(
        username=user_data['username'],
        first_name=user_data['first_name'],
        last_name=user_data['last_name'],
        email=user_data['email'],
        role=user_data.get('role', 'USER').upper(),
        active=user_data.get('active', True)
    )
    user.set_password(user_data['password'])

    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        "message": "User created",
        "user": user.to_dict()
    }), 201



from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

#Route-3: Get All Users Route   - Ok
@userBlueprint.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    claims = get_jwt()
    user_role = claims.get('role')

    if user_role == "ADMIN":
        users = User.query.all()
        data = []
        for user in users:
            data.append({
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'password':user.password,
                'role': user.role,
                'created_date': user.created_date,
                'updated_date': user.updated_date,
                'active': user.active
            })
        return jsonify({
            "message": "All Users",
            "users": data
        }), 200
    else:
        return jsonify({
            "message": "User have no access to get all users"
        }), 403



#Route-4: Get single user by ID Route - OK
@userBlueprint.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    claims = get_jwt()
    current_user_id = get_jwt_identity()
    user_role = claims.get('role')

    if user_role == "ADMIN":
        user = User.query.get_or_404(user_id)
    elif current_user_id == user_id:
        user = User.query.get_or_404(user_id)
    else:
        return jsonify({
            "message": "You don't have permission to access this user's information"
        }), 403

    return jsonify({
        "message": "User by user id",
        "user": user.to_dict()
    }), 200




#Route-5: Delete User by ID Route  - OK
@userBlueprint.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    current_user_id = get_jwt_identity()
    user_role = claims.get('role')

    if user_role == "ADMIN":
        user = User.query.get_or_404(user_id)
    elif user_role == "USER" and current_user_id == user_id:
        user = User.query.get_or_404(user_id)
    else:
        return jsonify({
            "message": "You don't have permission to delete this user"
        }), 403

    print("User Will Delete:", user)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200


#Route-5: Login User Route  - OK
@userBlueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    errors = user_login_schema.validate(data)
    if errors:
        return jsonify({
            "Message":"Username or Password not validate",
        }),400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({
            "Message":"Invalid credentials"
        }),401
    
    access_token = generate_token(user)
    return jsonify({
        "Message":"Login Successful",
        "Token":access_token
    })




#Route-6: Update User by ID
@userBlueprint.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    claims = get_jwt()
    current_user_id = get_jwt_identity()
    user_role = claims.get('role')

    # Check permissions
    if user_role != "ADMIN" and current_user_id != user_id:
        return jsonify({"error": "You don't have permission to update this user's information"}), 403

    user = User.query.get_or_404(user_id)
    
    data = request.get_json()
    
    update_schema = UpdateUserSchema(only=('first_name', 'last_name', 'email', 'role'))
    try:
        validated_data = update_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": err.messages}), 400

    # Update user information
    if 'first_name' in validated_data:
        user.first_name = validated_data['first_name']
    if 'last_name' in validated_data:
        user.last_name = validated_data['last_name']
    if 'email' in validated_data:
        if User.query.filter(User.email == validated_data['email'], User.id != user.id).first():
            return jsonify({"error": "Email already exists"}), 400
        user.email = validated_data['email']
    
    # Only allow role update if the current user is an admin
    if 'role' in validated_data and user_role == "ADMIN":
        user.role = validated_data['role']
    elif 'role' in validated_data and user_role != "ADMIN":
        return jsonify({"error": "Only admins can change user roles"}), 403

    # Commit the changes to the database
    db.session.commit()

    return jsonify({
        "message": "User information updated successfully",
        "user": user.to_dict()
    }), 200





# Add this route to your userBlueprint
@userBlueprint.route('/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate a secure token
    token = secrets.token_urlsafe(32)
    
    # Set token expiry (e.g., 1 hour from now)
    expiry = datetime.utcnow() + timedelta(hours=1)

    # Save the token and expiry to the user
    user.reset_token = token
    user.reset_token_expiry = expiry
    db.session.commit()

    # Create the reset link
    reset_link = url_for('user.reset_password', token=token, _external=True)

    # Send email
    subject = "Password Reset Request"
    body = f"Click the following link to reset your password: {reset_link}"
    send_email(user.email, subject, body)

    return jsonify({"message": "Password reset link sent to your email"}), 200

# Add this route to handle the actual password reset
@userBlueprint.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or user.reset_token_expiry < datetime.utcnow():
        return jsonify({"error": "Invalid or expired token"}), 400

    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"error": "New password is required"}), 400

    user.set_password(new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    db.session.commit()

    return jsonify({"message": "Password reset successful"}), 200
