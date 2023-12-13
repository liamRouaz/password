import sys
import random
import secrets
import hashlib

def generate_strong_password(length=12):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:'\",.<>?/"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def hash_password(password, salt=None, algorithm='sha256'):
    if salt is None:
        salt = secrets.token_hex(16)  # Génération d'un sel aléatoire
    hash_obj = hashlib.new(algorithm)
    password_with_salt = (password + salt).encode('utf-8')
    hash_obj.update(password_with_salt)
    hashed_password = hash_obj.hexdigest()
    return hashed_password, salt

def verify_password(raw_password, hashed_password, salt, algorithm='sha256'):
    # Vérification du mot de passe en rehashant le mot de passe fourni avec le sel stocké
    password_to_check, _ = hash_password(raw_password, salt, algorithm)
    return password_to_check == hashed_password

def main():
    # Argument vecteur : tableau pour pointer les chaînes de caractères
    quantity = sys.argv[1] if len(sys.argv) > 1 else 1
    quantity = int(quantity)

    for _ in range(quantity):
        # Générer un mot de passe fort
        password = generate_strong_password()

        # Générer le hachage du mot de passe
        hashed_password, salt = hash_password(password)

        print("Mot de passe généré:", password)
        print("Mot de passe haché:", hashed_password)
        print("Sel utilisé:", salt)

        # Simulation de la vérification du mot de passe
        is_password_correct = verify_password(password, hashed_password, salt)
        print("Le mot de passe est correct :", is_password_correct)
        print("\n")

if __name__ == "__main__":
    main()
