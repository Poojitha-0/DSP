from cryptography.fernet import Fernet

# Load the encryption key from the file
def load_key():
    with open('key_config.txt', 'rb') as key_file:
        return key_file.read()

# Initialize the Fernet object with the loaded key
KEY = load_key()
cipher = Fernet(KEY)

def encrypt_data(data):
    """Encrypts the given data."""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypts the given encrypted data."""
    return cipher.decrypt(encrypted_data.encode()).decode()
