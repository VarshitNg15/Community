from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from datetime import datetime
import os

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/communityspotter'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'home'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.role = user_doc['role']

    @staticmethod
    def get(user_id):
        user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_doc) if user_doc else None

@login_manager.user_loader
def load_user(user_id):
    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    login_error = None
    if request.method == 'POST':
        username = request.form['login_username']
        password = request.form['login_password']
        role = request.form['login_role']
        user_doc = mongo.db.users.find_one({'username': username, 'role': role})
        if user_doc and bcrypt.check_password_hash(user_doc['password'], password):
            user = User(user_doc)
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            login_error = 'Invalid credentials.'
    return render_template('home.html', login_error=login_error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    register_error = None
    if request.method == 'POST':
        username = request.form['register_username']
        password = request.form['register_password']
        confirm_password = request.form['register_confirm_password']
        role = request.form['register_role']
        if password != confirm_password:
            register_error = 'Passwords do not match.'
        elif mongo.db.users.find_one({'username': username, 'role': role}):
            register_error = 'User already exists.'
        else:
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            mongo.db.users.insert_one({'username': username, 'password': hashed_pw, 'role': role})
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('home'))
    return render_template('register.html', register_error=register_error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'user':
        flash('Unauthorized', 'danger')
        return redirect(url_for('admin_dashboard'))
    pending_issues = list(mongo.db.issues.find({'user_id': ObjectId(current_user.id), 'status': {'$ne': 'completed'}}))
    completed_issues = list(mongo.db.issues.find({'user_id': ObjectId(current_user.id), 'status': 'completed'}))
    return render_template('user_dashboard.html', pending_issues=pending_issues, completed_issues=completed_issues)

@app.route('/issue', methods=['GET', 'POST'])
@login_required
def issue():
    if current_user.role != 'user':
        flash('Unauthorized', 'danger')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        description = request.form['description']
        category = request.form['category']
        address = request.form.get('address')
        photo = request.files['photo']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        # Only allow address or map selection, not manual lat/lon entry
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)
        else:
            flash('Invalid photo file.', 'danger')
            return render_template('issue_form.html')
        issue_doc = {
            'user_id': ObjectId(current_user.id),
            'description': description,
            'category': category,
            'photo_filename': filename,
            'created_at': datetime.utcnow(),
            'votes': 0,
            'suggestions': [],
            'plan_of_execution': '',
            'status': 'pending',
            'address': address if address else None
        }
        # If map was used, store coordinates as well
        if latitude and longitude:
            issue_doc['latitude'] = float(latitude)
            issue_doc['longitude'] = float(longitude)
        mongo.db.issues.insert_one(issue_doc)
        flash('Issue submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('issue_form.html')

@app.route('/voting', methods=['GET', 'POST'])
@login_required
def voting():
    if current_user.role != 'user':
        flash('Unauthorized', 'danger')
        return redirect(url_for('admin_dashboard'))
    pending_issues = list(mongo.db.issues.find({'status': {'$ne': 'completed'}}))
    completed_issues = list(mongo.db.issues.find({'status': 'completed'}))
    voted_issue_ids = set(v['issue_id'] for v in mongo.db.votes.find({'user_id': ObjectId(current_user.id)}))
    if request.method == 'POST':
        issue_id = request.form['issue_id']
        if mongo.db.votes.find_one({'user_id': ObjectId(current_user.id), 'issue_id': ObjectId(issue_id)}):
            flash('You have already voted for this issue.', 'warning')
        else:
            mongo.db.votes.insert_one({'user_id': ObjectId(current_user.id), 'issue_id': ObjectId(issue_id), 'created_at': datetime.utcnow()})
            mongo.db.issues.update_one({'_id': ObjectId(issue_id)}, {'$inc': {'votes': 1}})
            flash('Vote submitted!', 'success')
        return redirect(url_for('voting'))
    for issue in pending_issues:
        issue['has_voted'] = str(issue['_id']) in [str(i) for i in voted_issue_ids]
    return render_template('voting.html', pending_issues=pending_issues, completed_issues=completed_issues)

@app.route('/suggestions/<issue_id>', methods=['GET', 'POST'])
@login_required
def suggestions(issue_id):
    if current_user.role != 'user':
        flash('Unauthorized', 'danger')
        return redirect(url_for('admin_dashboard'))
    issue = mongo.db.issues.find_one({'_id': ObjectId(issue_id)})
    suggestions = list(mongo.db.suggestions.find({'issue_id': ObjectId(issue_id)}))
    if request.method == 'POST':
        suggestion_text = request.form['suggestion']
        mongo.db.suggestions.insert_one({
            'user_id': ObjectId(current_user.id),
            'issue_id': ObjectId(issue_id),
            'suggestion': suggestion_text,
            'created_at': datetime.utcnow()
        })
        flash('Suggestion submitted!', 'success')
        return redirect(url_for('suggestions', issue_id=issue_id))
    return render_template('suggestions.html', issue_id=issue_id, suggestions=suggestions)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    issues = list(mongo.db.issues.find())
    suggestions_map = {}
    for issue in issues:
        suggestions_map[str(issue['_id'])] = list(mongo.db.suggestions.find({'issue_id': issue['_id']}))
    if request.method == 'POST':
        issue_id = request.form['issue_id']
        if 'plan' in request.form:
            plan = request.form['plan']
            mongo.db.issues.update_one({'_id': ObjectId(issue_id)}, {'$set': {'plan_of_execution': plan}})
            flash('Plan of execution updated!', 'success')
            return redirect(url_for('admin_dashboard'))
        elif 'complete' in request.form:
            mongo.db.issues.update_one({'_id': ObjectId(issue_id)}, {'$set': {'status': 'completed'}})
            flash('Issue marked as completed!', 'success')
            return redirect(url_for('admin_dashboard'))
    votes_map = {}
    for issue in issues:
        votes_map[str(issue['_id'])] = mongo.db.votes.count_documents({'issue_id': issue['_id']})
    return render_template('admin_dashboard.html', issues=issues, suggestions_map=suggestions_map, votes_map=votes_map)

@app.route('/admin/location/<issue_id>')
@login_required
def admin_location(issue_id):
    if current_user.role != 'admin':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    issue = mongo.db.issues.find_one({'_id': ObjectId(issue_id)})
    return render_template('admin_location.html', issue=issue)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True) 