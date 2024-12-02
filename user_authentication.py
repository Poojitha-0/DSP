import bcrypt
import pymysql

# Database connection
connection = pymysql.connect(
    host="localhost",
    user="root",       # Replace with your MySQL username
    password="Cheppanu@123",  # Replace with your MySQL password
    database="SecureFinanceDB"  # Replace with your database name
)

cursor = connection.cursor()

# Function to register a new user
def register_user(username, password, user_group):
    # Hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    # Insert user into the database
    query = "INSERT INTO Users (Username, PasswordHash, UserGroup) VALUES (%s, %s, %s)"
    try:
        cursor.execute(query, (username, hashed_password.decode('utf-8'), user_group))
        connection.commit()
        print(f"User '{username}' registered successfully!")
    except pymysql.err.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
    except Exception as e:
        print(f"Error: {e}")

# Function to authenticate user
def authenticate_user(username, password):
    # Fetch the stored password hash for the given username
    query = "SELECT PasswordHash FROM Users WHERE Username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result:
        stored_hash = result[0]
        # Check if the provided password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            print(f"Login successful! Welcome {username}.")
            return True
        else:
            print("Invalid password.")
            return False
    else:
        print("User not found.")
        return False

# Example usage for registration
register_user("alice", "SecurePassword123", "A")  # Admin user
register_user("bob", "AnotherPassword456", "V")   # Viewer user

# Example usage for authentication
authenticate_user("alice", "SecurePassword123")  # Should succeed
authenticate_user("bob", "WrongPassword")       # Should fail
authenticate_user("unknown", "Password123")     # User not found

# Close the database connection
cursor.close()
connection.close()
