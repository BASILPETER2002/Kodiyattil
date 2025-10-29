from flask import Flask, request, jsonify, session, make_response, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
import os
from datetime import timedelta, datetime
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

# --- Basic Setup ---
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static", template_folder="templates")

# --- CORS configuration ---
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5500", "http://localhost:5500"])

# --- Config ---
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-987654321'),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_COOKIE_NAME="kodiyattil_session",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_REFRESH_EACH_REQUEST=True,
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'gif'},
    MAX_CONTENT_LENGTH=5 * 1024 * 1024
)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kodiyattil.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# --- Models ---
class FamilyMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    generation = db.Column(db.String(50))
    can_edit = db.Column(db.Boolean, default=False)
    photo_url = db.Column(db.String(250), nullable=True)  # profile photo


class FamilyIntroduction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.String(100), unique=True, nullable=False)
    introduction = db.Column(db.Text, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.String(120), nullable=False)


class GalleryPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(250), nullable=False)
    uploaded_by = db.Column(db.String(120), nullable=False)
    upload_date = db.Column(db.String(50), nullable=False)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(50), nullable=False)


# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


def editor_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user_email = session['user']['email']
        member = FamilyMember.query.filter_by(email=user_email).first()
        if not member or not member.can_edit:
            return jsonify({"success": False, "error": "Insufficient permissions"}), 403
        return f(*args, **kwargs)
    return decorated_function


# --- Helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# =================================================================================
# ROUTES
# =================================================================================

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)


# ---------------- AUTH ----------------
@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user' in session:
        email = session['user']['email']
        member = FamilyMember.query.filter_by(email=email).first()
        if member:
            return jsonify({
                "authenticated": True,
                "user": {
                    "id": member.id,
                    "email": member.email,
                    "name": member.name,
                    "generation": member.generation,
                    "can_edit": member.can_edit,
                    "photo_url": member.photo_url
                }
            })
    return jsonify({"authenticated": False})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    member = FamilyMember.query.filter_by(email=email).first()
    if member and check_password_hash(member.password, password):
        session.permanent = True
        session['user'] = {"email": member.email}
        return jsonify({"success": True, "user": {
            "id": member.id,
            "name": member.name,
            "generation": member.generation,
            "can_edit": member.can_edit,
            "photo_url": member.photo_url
        }})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    response = make_response(jsonify({"success": True}))
    response.set_cookie('session', '', expires=0)
    return response


# ---------------- PROFILE PHOTO ----------------
@app.route('/api/edit-photo', methods=['POST'])
@login_required
def edit_photo():
    if 'photo' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['photo']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file type"}), 400

    user_email = session['user']['email']
    member = FamilyMember.query.filter_by(email=user_email).first()

    if not member:
        return jsonify({"success": False, "error": "User not found"}), 404

    # Save file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"profile_{member.id}_{timestamp}_{secure_filename(file.filename)}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Update DB
    member.photo_url = f"/static/uploads/{filename}"
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Profile photo updated successfully",
        "photoUrl": member.photo_url
    })


@app.route('/api/member-photo/<int:member_id>', methods=['GET'])
def get_member_photo(member_id):
    member = FamilyMember.query.get(member_id)
    if member and member.photo_url:
        return jsonify({"success": True, "photoUrl": member.photo_url})
    return jsonify({"success": False, "error": "Photo not found"}), 404


# ---------------- INTRODUCTIONS ----------------
@app.route('/api/introduction/<member_id>', methods=['GET'])
def get_introduction(member_id):
    intro = FamilyIntroduction.query.filter_by(member_id=member_id).first()
    if intro:
        return jsonify({
            "success": True,
            "introduction": intro.introduction,
            "last_updated": intro.last_updated.strftime("%B %d, %Y"),
            "updated_by": intro.updated_by
        })
    return jsonify({"success": False, "introduction": ""})


@app.route('/api/introduction/<member_id>', methods=['POST'])
@login_required
def update_introduction(member_id):
    data = request.get_json()
    introduction_text = data.get('introduction', '').strip()
    
    # Get current user
    user_email = session['user']['email']
    member = FamilyMember.query.filter_by(email=user_email).first()
    
    # Check if introduction exists
    intro = FamilyIntroduction.query.filter_by(member_id=member_id).first()
    
    if intro:
        intro.introduction = introduction_text
        intro.last_updated = datetime.utcnow()
        intro.updated_by = member.name
    else:
        intro = FamilyIntroduction(
            member_id=member_id,
            introduction=introduction_text,
            updated_by=member.name
        )
        db.session.add(intro)
    
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": "Introduction updated successfully",
        "introduction": intro.introduction,
        "last_updated": intro.last_updated.strftime("%B %d, %Y"),
        "updated_by": intro.updated_by
    })


# ---------------- GALLERY ----------------
@app.route("/api/upload-photo", methods=["POST"])
@login_required
def upload_photo():
    if "photos" not in request.files:
        return jsonify({"success": False, "error": "No files uploaded"}), 400

    uploaded_files = request.files.getlist("photos")
    saved_files = []
    user_email = session['user']['email']

    for file in uploaded_files:
        if file and allowed_file(file.filename):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{secure_filename(file.filename)}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)

            file_url = f"/static/uploads/{filename}"
            saved_files.append(file_url)

            photo = GalleryPhoto(filename=filename, url=file_url,
                                 uploaded_by=user_email,
                                 upload_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            db.session.add(photo)

    db.session.commit()
    return jsonify({"success": True, "files": saved_files})


@app.route('/api/gallery', methods=['GET'])
def get_gallery():
    photos = GalleryPhoto.query.all()
    gallery = [{
        "url": p.url,
        "uploaded_by": p.uploaded_by,
        "upload_date": p.upload_date,
        "filename": p.filename
    } for p in photos]
    return jsonify({"success": True, "gallery": gallery})


@app.route("/api/delete-photo", methods=["POST"])
@login_required
def delete_photo():
    data = request.get_json()
    filename = data.get('filename')
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400

    user_email = session['user']['email']
    photo = GalleryPhoto.query.filter_by(filename=filename).first()

    if not photo:
        return jsonify({"success": False, "error": "Photo not found"}), 404

    member = FamilyMember.query.filter_by(email=user_email).first()
    if photo.uploaded_by != user_email and not member.can_edit:
        return jsonify({"success": False, "error": "You can only delete your own photos"}), 403

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(photo)
        db.session.commit()
        return jsonify({"success": True, "message": "Photo deleted successfully"})
    except Exception as e:
        logger.error(f"Delete error: {e}")
        return jsonify({"success": False, "error": "Failed to delete photo"}), 500


# ---------------- NOTIFICATIONS ----------------
@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    notes = Notification.query.order_by(Notification.id.desc()).all()
    return jsonify({"success": True, "notifications": [
        {"title": n.title, "message": n.message, "date": n.date} for n in notes
    ]})


@app.route('/api/notifications', methods=['POST'])
@editor_required
def add_notification():
    data = request.get_json()
    title, message = data.get('title'), data.get('message')
    if not title or not message:
        return jsonify({"success": False, "error": "Title and message required"}), 400

    note = Notification(title=title, message=message,
                        date=datetime.now().strftime("%B %d, %Y"))
    db.session.add(note)
    db.session.commit()
    return jsonify({"success": True, "notification": {
        "title": note.title, "message": note.message, "date": note.date
    }}), 201

@app.route('/api/family-locations', methods=['GET'])
def get_family_locations():
    # This should return data matching your frontend expectations
    members = [
        {
            "id": "pathrose-mariyam", 
            "name": "Pathrose & Mariyam Kodiyattil", 
            "branch": "great-grandparents", 
            "generation": 1, 
            "lat": 9.9312, 
            "lng": 76.2673,
            "city": "Peravoor, Kannur, Kerala, India"
        },
        {
            "id": "teena-jijin", 
            "name": "Teena & Jijin C", 
            "branch": "mathew", 
            "generation": 4, 
            "lat": -28.2211, 
            "lng": 152.0314,
            "city": "Warwick, Australia"
        }
        # Add all other family members here
    ]
    return jsonify({"success": True, "members": members})

# ---------------- FILE SERVING ----------------
@app.route('/static/uploads/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------------- Security Headers ----------------
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://127.0.0.1:5500')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed default members if missing
        if not FamilyMember.query.filter_by(email="basil@kodiyattil.com").first():
            db.session.add(FamilyMember(
                email="basil@kodiyattil.com",
                password=generate_password_hash("Family@123"),
                name="Admin 1",
                phone="9061159621",
                generation="3rd",
                can_edit=True
            ))
        if not FamilyMember.query.filter_by(email="teena@kodiyattil.com").first():
            db.session.add(FamilyMember(
                email="teena@kodiyattil.com",
                password=generate_password_hash("Teena@2023"),
                name="Admin 2",
                phone="9895000000",
                generation="4th",
                can_edit=True
            ))
        if not Notification.query.first():
            db.session.add(Notification(
                title="Family Gathering",
                message="All family members are invited to our annual reunion at the family house.",
                date="June 15, 2024 at 5:00 PM"
            ))
        db.session.commit()

    app.run(debug=True, host='0.0.0.0', port=5000)