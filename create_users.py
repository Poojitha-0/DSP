import pymysql
import bcrypt

# Initialize MySQL connection
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Cheppanu@123',
    database='SecureFinanceDB'
)
cursor = connection.cursor()

# Function to hash password
def hash_password(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode()

# Fetch unique customer names from FinancialTransactions
cursor.execute("SELECT DISTINCT CustomerName FROM FinancialTransactions;")
customer_names = cursor.fetchall()

if not customer_names:
    print("No customer names found in FinancialTransactions!")
else:
    print(f"Found {len(customer_names)} unique customer names.")

# Insert each customer name into the Users table
for customer_name in customer_names:
    username = customer_name[0]  # Extract name from tuple
    password = "Password123"  # Set a default password
    hashed_password = hash_password(password)
    user_group = "V"  # Set UserGroup as 'V'

    try:
        print(f"Inserting user: {username}")  # Debug print
        cursor.execute("""
        INSERT INTO Users (Username, PasswordHash, UserGroup)
        VALUES (%s, %s, %s);
        """, (username, hashed_password, user_group))
    except Exception as e:
        print(f"Error inserting user {username}: {e}")

# Commit the transaction
connection.commit()
print("Users table populated successfully!")

# Close the connection
connection.close()
