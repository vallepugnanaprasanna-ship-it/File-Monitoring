
from database import create_table, register_file, get_all_files
from hash_generator import generate_hash

create_table()

file_path = "monitorerd_files/sample.txt"

file_hash = generate_hash(file_path)

if file_hash:
    register_file(file_path, file_hash)
    print("File registered successfully!")

    print("\nRegistered Files:")

    for record in get_all_files():
        print(record)
else:
    print("File not found!")
