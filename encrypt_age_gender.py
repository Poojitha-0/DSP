import pymysql
from cryptography.fernet import Fernet

# Loading the key from the file
with open('key_config.txt', 'rb') as key_file:
    key = key_file.read()
cipher = Fernet(key)

def encrypt_data():
    connection = pymysql.connect(
        host='localhost',  # Replace with your host
        user='root',       # Replace with your database user
        password='Cheppanu@123',  # Replace with your database password
        db='SecureFinanceDB'
    )
    cursor = connection.cursor()

    # Fetch all records from HealthcareInfo
    cursor.execute("SELECT id, FirstName, LastName, Gender, Age, Weight, Height, HealthHistory FROM HealthcareInfo")
    records = cursor.fetchall()

    for record in records:
        id = record[0]  # The 'id' field is now at index 0
        firstname = record[1]
        lastname = record[2]
        gender = record[3]  # Gender field at index 3
        age = record[4]     # Age field at index 4
        weight = record[5]
        height = record[6]
        healthhistory = record[7]

        # Encrypt the Age and Gender fields
        encrypted_age = cipher.encrypt(str(age).encode()).decode()  # Encrypting Age
        encrypted_gender = cipher.encrypt(str(gender).encode()).decode()  # Encrypting Gender

        # Update the record in the database with encrypted Age and Gender
        cursor.execute("""
        UPDATE HealthcareInfo 
        SET Gender = %s, Age = %s 
        WHERE id = %s
        """, (encrypted_gender, encrypted_age, id))

    connection.commit()
    connection.close()

# Call the function to update the data
encrypt_data()
