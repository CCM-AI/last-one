from flask import Flask, request, redirect, url_for, render_template, session
from flask_sqlalchemy import SQLAlchemy
import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chronic_care.db'  # Change to your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define your database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Initialize the database and create tables
def initialize_database():
    with app.app_context():
        db.create_all()  # Create the database and tables if they don't exist

# Function to check if a user exists
def user_exists(username):
    with app.app_context():  # Ensure we're in the app context
        return User.query.filter_by(username=username).first() is not None

# Function to add a new user
def add_user(username, password):
    with app.app_context():  # Ensure we're in the app context
        hashed_password = generate_password_hash(password)  # Omit the method to use default
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

# Streamlit main function
def main():
    initialize_database()  # Ensure the database and tables are created

    # Streamlit UI
    st.title("Chronic Care Management System")
    
    # Authentication
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Login":
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type='password')
        
        if st.sidebar.button("Login"):
            with app.app_context():  # Ensure we're in the app context
                user = User.query.filter_by(username=username).first()
                if user and check_password_hash(user.password, password):
                    st.success("Logged in successfully!")
                    # Here you can display more features for logged-in users
                else:
                    st.error("Invalid username or password.")

    elif choice == "Register":
        new_username = st.sidebar.text_input("New Username")
        new_password = st.sidebar.text_input("New Password", type='password')
        
        if st.sidebar.button("Register"):
            if user_exists(new_username):
                st.error("Username already exists.")
            else:
                add_user(new_username, new_password)
                st.success("User registered successfully!")

if __name__ == "__main__":
    main()
# Function to show user dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# Update the main function to include a dashboard link
def main():
    initialize_database()  # Ensure the database and tables are created

    # Streamlit UI
    st.title("Chronic Care Management System")
    
    # Authentication
    menu = ["Login", "Register", "Dashboard"]  # Added Dashboard option
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Login":
        # Existing login code...
    
    elif choice == "Register":
        # Existing registration code...
    
    elif choice == "Dashboard":
        if 'username' in session:
            st.write(f"Welcome to your dashboard, {session['username']}!")
            # Additional dashboard functionality can be added here.
        else:
            st.error("You need to be logged in to access the dashboard.")

if __name__ == "__main__":
    app.run(debug=True)
