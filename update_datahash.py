import pymysql
import hashlib

def update_data_hash():
    try:
        # Connect to the database
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password='Cheppanu@123',
            database='SecureFinanceDB'
        )
        cursor = connection.cursor()

        # Retrieve all data from HealthcareInfo table
        cursor.execute("SELECT ID, FirstName, LastName, Gender, Age, Weight, Height, HealthHistory FROM HealthcareInfo")
        rows = cursor.fetchall()

        # Update DataHash for each record
        for row in rows:
            # Concatenate the row data into a single string
            row_data = ''.join(str(field) for field in row[1:])  # excluding ID column
            # Calculate the SHA-256 hash
            data_hash = hashlib.sha256(row_data.encode()).hexdigest()

            # Update the DataHash value in the table
            cursor.execute(
                "UPDATE HealthcareInfo SET DataHash = %s WHERE ID = %s",
                (data_hash, row[0])  # row[0] is the ID
            )

        # Commit the changes
        connection.commit()
        print("DataHash values updated successfully!")

    except Exception as e:
        print(f"Error updating DataHash values: {e}")

    finally:
        # Close the database connection
        cursor.close()
        connection.close()

# Run the update function
update_data_hash()
