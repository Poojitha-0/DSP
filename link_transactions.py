import pymysql

# Initialize MySQL connection
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Cheppanu@123',
    database='SecureFinanceDB'
)
cursor = connection.cursor()

# Fetch customer names and their corresponding IDs from the Users table
cursor.execute("SELECT id, Username FROM Users")
user_data = cursor.fetchall()

# Link users to transactions based on the customer names in FinancialTransactions table
for user_id, username in user_data:
    # Fetch transactions for the customer
    cursor.execute("""
    SELECT amount, transaction_type 
    FROM FinancialTransactions 
    WHERE customer_name = %s
    """, (username,))
    
    transactions = cursor.fetchall()
    
    # Insert transactions into the Transactions table
    for transaction in transactions:
        amount, transaction_type = transaction
        cursor.execute("""
        INSERT INTO Transactions (user_id, amount, transaction_type)
        VALUES (%s, %s, %s)
        """, (user_id, amount, transaction_type))

connection.commit()
connection.close()

print("Transactions have been added successfully for each user!")
