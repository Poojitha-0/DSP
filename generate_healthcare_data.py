import pymysql
import random
from faker import Faker

# Initialize Faker and MySQL connection
fake = Faker()
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Cheppanu@123',
    database='SecureFinanceDB'
)
cursor = connection.cursor()

# Query to fetch FirstName and LastName from UserNames table
cursor.execute("SELECT FirstName, LastName FROM UserNames")
users = cursor.fetchall()

# Helper function to generate random values for columns
def generate_random_data():
    gender = random.choice([True, False])  # Randomly select True or False for gender
    age = random.randint(18, 80)  # Random age between 18 and 80
    weight = round(random.uniform(50, 100), 2)  # Random weight between 50kg and 100kg
    height = round(random.uniform(150, 190), 2)  # Random height between 150cm and 190cm
    health_history = fake.text(max_nb_chars=200)  # Generate random health history text
    return gender, age, weight, height, health_history

# Insert data into HealthcareInfo table
for first_name, last_name in users:
    gender, age, weight, height, health_history = generate_random_data()
    
    cursor.execute("""
    INSERT INTO HealthcareInfo (FirstName, LastName, Gender, Age, Weight, Height, HealthHistory)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (first_name, last_name, gender, age, weight, height, health_history))

# Commit the changes and close the connection
connection.commit()
connection.close()

print("Healthcare information has been successfully added to the table!")
