"""Cree le tout premier compte administrateur.

POST /users est reserve aux admins (pas d'auto-inscription sur un outil de
suivi de vulnerabilites), donc le tout premier compte doit etre cree en
direct contre la base, avant qu'un admin existe pour en creer d'autres via
l'API. A executer une seule fois, a la mise en place de l'instance.

Usage:
    python -m scripts.create_admin --username amiir --password "un-mot-de-passe-solide"
"""
import argparse
import getpass
import sys

sys.path.insert(0, ".")

from app import models  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.database import SessionLocal  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--password",
        help="Si omis, demande sur l'entree standard (plus sur : n'apparait pas dans l'historique shell).",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Mot de passe: ")
    if len(password) < 12:
        print("Le mot de passe doit faire au moins 12 caracteres.", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    try:
        existing = db.query(models.User).filter_by(username=args.username).first()
        if existing:
            print(f"L'utilisateur '{args.username}' existe deja.", file=sys.stderr)
            sys.exit(1)

        user = models.User(
            username=args.username,
            hashed_password=hash_password(password),
            role="admin",
        )
        db.add(user)
        db.commit()
        print(f"Compte admin '{args.username}' cree.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
