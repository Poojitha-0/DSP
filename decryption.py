# decryption.py
from cryptography.fernet import Fernet

def load_encryption_key():
    with open('key_config.txt', 'rb') as key_file:
        return key_file.read()

# Initialize cipher suite
key = load_encryption_key()
cipher_suite = Fernet(key)

def decrypt_data(encrypted_data):
    """Decrypt the given encrypted data."""
    return cipher_suite.decrypt(encrypted_data).decode()

def decrypt_healthcare_data(healthcare_data):
    """Decrypt sensitive healthcare data (e.g., Gender, Age)."""
    decrypted_data = list(healthcare_data)  # Make a copy to avoid modifying the original tuple
    decrypted_data[2] = decrypt_data(healthcare_data[2])  # Decrypt Gender
    decrypted_data[3] = int(decrypt_data(healthcare_data[3]))  # Decrypt Age
    return decrypted_data
