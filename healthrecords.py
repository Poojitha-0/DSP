import pymysql
from faker import Faker

# Initialize Faker
fake = Faker()

# Connect to the MySQL database
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Cheppanu@123',
    database='SecureFinanceDB'
)

cursor = connection.cursor()

# Generate 200 random health history reasons
health_history_reasons = []
for _ in range(200):
    health_history = " ".join(fake.sentences(nb=5))  # Generate 5 random sentences
    health_history_reasons.append(health_history)

# Insert health histories into the HealthcareInfo table
try:
    # Fetch the existing IDs for the rows in the HealthcareInfo table
    cursor.execute("SELECT COUNT(*) FROM HealthcareInfo;")
    row_count = cursor.fetchone()[0]

    if row_count < 200:
        print(f"Existing rows: {row_count}. Inserting {200 - row_count} rows...")

        # Insert random health histories
        for idx in range(row_count, 200):
            health_history = health_history_reasons[idx]
            cursor.execute("""
                UPDATE HealthcareInfo
                SET HealthHistory = %s
                WHERE FirstName = (SELECT FirstName FROM UserNames LIMIT 1 OFFSET %s)
                AND LastName = (SELECT LastName FROM UserNames LIMIT 1 OFFSET %s)
            """, (health_history, idx, idx))

    connection.commit()
    print("Health history reasons have been successfully updated!")
except Exception as e:
    print("An error occurred:", e)
finally:
    connection.close()
