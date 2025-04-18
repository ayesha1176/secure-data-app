import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# Generate a key (should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Load data from JSON file if exists
DATA_FILE = "stored_data.json"
try:
    with open(DATA_FILE, "r") as file:
        stored_data = json.load(file)
except FileNotFoundError:
    stored_data = {}

# Track failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Save data to file
def save_data():
    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

# Streamlit UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app lets you store and retrieve encrypted data using a passkey.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter the data you want to store")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt and Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            save_data()
            st.success("✅ Data encrypted and saved!")
        else:
            st.error("⚠️ Please fill in all fields!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste the encrypted data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"✅ Decrypted Text: {result}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Login")
    master = st.text_input("Enter master password to reset", type="password")

    if st.button("Login"):
        if master == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in. You can now retry decryption.")
        else:
            st.error("❌ Wrong password!")
