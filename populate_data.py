import pymysql
from faker import Faker

# Database connection
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Cheppanu@123',
    database='SecureFinanceDB'
)

cursor = connection.cursor()
fake = Faker()

success_count = 0

for _ in range(100):
    query = """
    INSERT INTO FinancialTransactions (CustomerName, AccountNumber, TransactionType, TransactionAmount, AccountBalance, TransactionDate)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (
        fake.name(),
        fake.unique.bban(),
        fake.random_element(elements=('Credit', 'Debit')),
        round(fake.pyfloat(left_digits=4, right_digits=2, positive=True), 2),
        round(fake.pyfloat(left_digits=5, right_digits=2, positive=True), 2),
        fake.date_between(start_date='-1y', end_date='today')
    )
    try:
        cursor.execute(query, values)
        success_count += 1
    except Exception as e:
        print(f"Error inserting record {_}: {e}")

connection.commit()
print(f"Dummy data inserted successfully! Total: {success_count}")
cursor.close()
connection.close()
