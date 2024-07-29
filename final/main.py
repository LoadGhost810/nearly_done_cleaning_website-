from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            profile_pic TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            service TEXT,
            date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        conn.commit()

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

init_db()

def is_logged_in():
    return 'username' in session

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['name']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['user_id'] = user['id']
            flash('You have successfully signed in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/sign_up', methods=['POST'])
def sign_up():
    username = request.form['new_name']
    email = request.form['new_email']
    password = request.form['new_password']
    retype_password = request.form['retype_password']

    if password != retype_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('login'))
    
    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()
        flash('You have successfully signed up!', 'success')
    except sqlite3.IntegrityError as e:
        flash(str(e), 'danger')
    
    return redirect(url_for('login'))

@app.route('/contact')
def contact():
    if not is_logged_in():
        flash('You need to be logged in to access this page', 'danger')
        return redirect(url_for('login'))
    return render_template('contact.html')
    
@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if not is_logged_in():
        flash('You need to be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    user = session.get('username')
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    user_email = cursor.fetchone()
    conn.close()

    email = user_email['email'] if user_email else ""

    if request.method == 'POST':
        service = request.form['service']
        date = request.form['date']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO bookings (user_id, service, date) VALUES (?, ?, ?)', (user_id, service, date))
        conn.commit()
        conn.close()
        
        flash('Booking submitted successfully', 'success')
        return redirect(url_for('account'))

    return render_template('booking.html', user=user, email=email)

@app.route('/gallery')
def gallery():
    if not is_logged_in():
        flash('You need to be logged in to access this page', 'danger')
        return redirect(url_for('login'))
    return render_template('gallery.html')

@app.route('/account')
def account():
    if not is_logged_in():
        flash('You need to be logged in to access this page', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM bookings WHERE user_id = ?', (user_id,))
    bookings = cursor.fetchall()
    cursor.execute('SELECT username, profile_pic FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('account.html', username=user['username'], bookings=bookings, profile_pic=user['profile_pic'])

@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    if not is_logged_in():
        flash('You need to be logged in to perform this action', 'danger')
        return redirect(url_for('login'))

    file = request.files['profile_picture']
    
    if file and allowed_file(file.filename):
        filename = f"{session['user_id']}_{file.filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (filename, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Profile picture updated successfully!', 'success')
    else:
        flash('Invalid file type. Please upload a PNG, JPG, JPEG, or GIF image.', 'danger')

    return redirect(url_for('account'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))
@app.route("/thank_you")
def thank_you():
    return render_template('thank_you.html')

if __name__ == "__main__":
    app.run(port=5500, debug=True)
