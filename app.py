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
            if User.query.filter_by(username=new_username).first():
                st.error("Username already exists.")
            else:
                hashed_password = generate_password_hash(new_password, method='sha256')
                new_user = User(username=new_username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                st.success("User registered successfully!")

if __name__ == "__main__":
    main()
