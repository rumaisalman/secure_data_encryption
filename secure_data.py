import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)
    if data and data["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve encrypted data securely with passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language='text')
        else:
            st.error("⚠️ Enter both data and passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Too many failed attempts. Please login first.")
        st.switch_page("Login")
    else:
        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Enter Encrypted Text:")
        passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Decrypt"):
            if encrypted_input and passkey:
                result = decrypt_data(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted Data: {result}")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.authorized = False
                        st.warning("🚫 Too many failed attempts. Please login.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Provide both fields.")

elif choice == "Login":
    st.subheader("🔑 Reauthorize")
    master_password = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized! You may now retry.")
        else:
            st.error("❌ Incorrect master password.")
