import hashlib

# Data values from the database
first_name = "Timothy"
last_name = "Sweeney"
gender = "0"  # Gender as string
age = "39"
weight = "95.54"
height = "183.53"
health_history = "General health checkup"

# Concatenate values exactly as they are in the database (no spaces)
data_string = first_name + last_name + gender + age + weight + height + health_history

# Compute the SHA-256 hash
computed_hash = hashlib.sha256(data_string.encode()).hexdigest()

print(f"Computed Hash: {computed_hash}")
