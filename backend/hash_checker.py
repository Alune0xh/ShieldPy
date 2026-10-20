import hashlib
import os

class HashChecker:
    def new_hash(self, filepath):
        hash256 = hashlib.sha256() 
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hash256.update(chunk)
        return hash256.hexdigest()

    def hash_changed(self, saved_hash, filepath):
        return self.new_hash(filepath) != saved_hash
    
    def file_size(self, filepath):
        return os.path.getsize(filepath) if os.path.exists(filepath) else 0

