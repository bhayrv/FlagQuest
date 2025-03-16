from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/flagquest"
mongo = PyMongo(app)

# ---------------------------
# Realistic Challenges Dictionary
# ---------------------------
challenges = {
    1: {
        "title": "Basic Web Challenge",
        "description": "Check the page source to find hidden clues and retrieve the flag.",
        "category": "Web Security",
        "flag": "flag{basic_web_challenge}",
        "hint": "Right-click → View Page Source. Keep an eye out for hidden comments or parameters.",
        "points": 100
    },
    2: {
        "title": "SQL Injection Challenge",
        "description": (
            "An insecure login form might allow you to bypass authentication or extract data "
            "from the database. Try typical SQL injection payloads."
        ),
        "category": "Web Security",
        "flag": "flag{sql_injection_success}",
        "hint": "Use common SQL injection techniques like ' OR '1'='1' --",
        "points": 200
    },
    3: {
        "title": "Cross-Site Scripting (XSS)",
        "description": (
            "Find a vulnerable input field that doesn't sanitize user input, and inject a "
            "malicious script to display an alert."
        ),
        "category": "Web Security",
        "flag": "flag{xss_attack_success}",
        "hint": "Look for a parameter in the URL or form input that reflects your input back onto the page.",
        "points": 150
    },
    4: {
        "title": "Basic Cryptography",
        "description": "Decode a Base64 string and see if you can decrypt the hidden message.",
        "category": "Cryptography",
        "flag": "flag{crypto_decrypted}",
        "hint": "Use an online Base64 decoder or a command-line tool like base64.",
        "points": 100
    },
    5: {
        "title": "Command Injection",
        "description": (
            "A vulnerable parameter might allow OS commands to run on the server. "
            "Find the parameter and run 'whoami' or 'ls' to discover the flag."
        ),
        "category": "System Security",
        "flag": "flag{cmd_injection_found}",
        "hint": "Look for a field that might pass your input to a system command (ping, for example).",
        "points": 250
    }
}

# ---------------------------
# Learning Items Dictionary
# ---------------------------
learning_items = {
    1: {
        "title": "Introduction to Cyber Security",
        "description": (
            "Learn the basics of cyber security, the CIA triad (Confidentiality, Integrity, "
            "Availability), and common threat actors."
        ),
        "resources": [
            {
                "title": "What is Cyber Security? (CISA)",
                "url": "https://www.cisa.gov/uscert/ncas/tips/ST04-001"
            },
            {
                "title": "TryHackMe Pre-Security Path (Free Intro)",
                "url": "https://tryhackme.com/path/outline/presecurity"
            }
        ]
    },
    2: {
        "title": "Linux Fundamentals",
        "description": (
            "Understand the basics of Linux, commonly used commands, and how to set up a "
            "hacking environment."
        ),
        "resources": [
            {
                "title": "Kali Linux Official Docs",
                "url": "https://www.kali.org/docs/"
            },
            {
                "title": "Linux Fundamentals (TryHackMe)",
                "url": "https://tryhackme.com/room/linuxfundamentals"
            }
        ]
    },
    3: {
        "title": "Web Security Basics",
        "description": (
            "Dive into the fundamentals of web security, including the OWASP Top 10. "
            "Learn about common vulnerabilities like SQL injection, XSS, and more."
        ),
        "resources": [
            {
                "title": "OWASP Top 10 Official Page",
                "url": "https://owasp.org/www-project-top-ten/"
            },
            {
                "title": "PortSwigger Web Security Academy",
                "url": "https://portswigger.net/web-security"
            }
        ]
    },
    4: {
        "title": "Cryptography 101",
        "description": (
            "An introduction to encryption, hashing, and how cryptography protects information "
            "in transit and at rest."
        ),
        "resources": [
            {
                "title": "Cryptography Basics (Stanford)",
                "url": "https://crypto.stanford.edu/~dabo/cs255/"
            },
            {
                "title": "Practical Cryptography (MDN)",
                "url": "https://developer.mozilla.org/en-US/docs/Web/Security"
            }
        ]
    }
}

# ---------------------------
# Set up Login Manager
# ---------------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict['_id'])
        self.username = user_dict['username']
        self.password = user_dict['password']
        self.points = user_dict.get('points', 0)
        self.badges = user_dict.get('badges', [])

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None

# ---------------------------
# Registration and Login Routes
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if mongo.db.users.find_one({"username": username}):
            flash("Username already exists!")
            return redirect(url_for('register'))
        new_user = {
            "username": username,
            "password": generate_password_hash(password),
            "points": 0,
            "badges": []
        }
        mongo.db.users.insert_one(new_user)
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_doc = mongo.db.users.find_one({"username": username})
        if user_doc and check_password_hash(user_doc['password'], password):
            user = User(user_doc)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ---------------------------
# Main Application Routes
# ---------------------------
@app.route('/')
def index():
    return render_template('index.html', challenges=challenges)

@app.route('/learning_items')
def learning_items_route():
    return render_template('learning_items.html', learning_items=learning_items)

@app.route('/dashboard')
@login_required
def dashboard():
    progress_docs = mongo.db.challenge_progress.find({"user_id": current_user.id})
    completed_ids = [doc['challenge_id'] for doc in progress_docs]
    completed_challenges = {cid: challenges[cid] for cid in completed_ids if cid in challenges}
    user_doc = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    points = user_doc.get("points", 0)
    return render_template('dashboard.html', points=points, completed=completed_challenges)

@app.route('/learning_paths')
def learning_paths():
    paths = {}
    for cid, chal in challenges.items():
        cat = chal.get("category", "General")
        paths.setdefault(cat, []).append((cid, chal))
    return render_template('learning_paths.html', paths=paths)

@app.route('/challenge/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def challenge(challenge_id):
    # Progressive unlocking: ensure previous challenge is completed
    if challenge_id > 1:
        if not mongo.db.challenge_progress.find_one({"user_id": current_user.id, "challenge_id": challenge_id - 1}):
            flash("Please complete the previous challenge to unlock this one!")
            return redirect(url_for('challenge', challenge_id=challenge_id - 1))
    
    challenge = challenges.get(challenge_id)
    if not challenge:
        flash("Challenge not found!")
        return redirect(url_for('index'))
    
    message = None
    if request.method == 'POST':
        if request.form.get('action') == 'hint':
            message = f"Hint: {challenge['hint']}"
            mongo.db.users.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$inc": {"points": -10}}
            )
        else:
            user_flag = request.form.get('flag')
            if user_flag == challenge["flag"]:
                message = "Correct! You solved the challenge!"
                if not mongo.db.challenge_progress.find_one({"user_id": current_user.id, "challenge_id": challenge_id}):
                    mongo.db.users.update_one(
                        {"_id": ObjectId(current_user.id)},
                        {"$inc": {"points": challenge['points']}}
                    )
                    mongo.db.challenge_progress.insert_one({
                        "user_id": current_user.id,
                        "challenge_id": challenge_id
                    })
            else:
                message = "Incorrect flag, try again."
    return render_template('challenge.html', challenge=challenge, message=message)

# ---------------------------
# Real-Time Leaderboard API
# ---------------------------
@app.route('/api/leaderboard')
def leaderboard_api():
    top_users = mongo.db.users.find().sort("points", -1).limit(10)
    leaderboard_data = [{"username": u["username"], "points": u.get("points", 0)} for u in top_users]
    return jsonify(leaderboard_data)

# ---------------------------
# Leaderboard Page Route
# ---------------------------
@app.route('/leaderboard')
def leaderboard_page():
    top_users = list(mongo.db.users.find().sort("points", -1).limit(10))
    return render_template("leaderboard.html", leaderboard=top_users)

# ---------------------------
# Admin Panel Example for Adding Challenges
# ---------------------------
@app.route('/admin/add_challenge', methods=['GET', 'POST'])
@login_required
def add_challenge():
    if current_user.username != 'admin':
        flash("Access denied.")
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        flag = request.form.get('flag')
        hint = request.form.get('hint')
        category = request.form.get('category')
        points = int(request.form.get('points'))
        flash("Challenge added! (Implement persistent storage for challenges.)")
        return redirect(url_for('index'))
    return render_template('admin_add_challenge.html')

if __name__ == '__main__':
    app.run(debug=True)
