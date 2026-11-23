import hashlib
password_hash = hashlib.sha256(password).hexdigest()
