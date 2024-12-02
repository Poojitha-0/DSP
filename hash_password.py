import bcrypt

# Password to be hashed
plain_password = "Cheppanu@123"

# Generate a salt and hash the password
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(plain_password.encode(), salt)

print("Hashed Password:", hashed_password.decode())
