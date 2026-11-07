
import hashlib

def generate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except FileNotFoundError:
        return None


if __name__ == "__main__":
    path = input("Enter file path: ")
    result = generate_hash(path)

    if result:
        print("SHA-256 Hash:", result)
    else:
        print("File not found!")
