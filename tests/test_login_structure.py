"""Tests de structure du formulaire de login.

Regression : le login.html avait deux <form> distincts, le champ CSRF
dans le premier, les identifiants dans le second. Le navigateur ne
soumettait que le second -> le token n'etait jamais envoye -> "Session
expiree". curl reussissait quand meme (il extrait le token du HTML brut
sans tenir compte des balises), ce qui a masque le bug longtemps.

La lecon : verifier la *presence* du token ('name="csrf_token"' in html)
serait VERT avec le bug. Il faut verifier la *structure* : un seul form,
et le token IMBRIQUE dedans. D'ou un vrai parseur HTML.
"""
from html.parser import HTMLParser


class _LoginFormInspector(HTMLParser):
    """Suit la profondeur des <form> et localise le champ csrf_token."""

    def __init__(self) -> None:
        super().__init__()
        self.form_count = 0          # nombre total de <form> ouverts
        self._form_depth = 0         # profondeur courante d'imbrication form
        self.csrf_count = 0          # nombre de champs csrf_token
        self.csrf_inside_form = False  # au moins un csrf vu dans un form

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.form_count += 1
            self._form_depth += 1
        elif tag == "input":
            attributes = dict(attrs)
            if attributes.get("name") == "csrf_token":
                self.csrf_count += 1
                if self._form_depth > 0:
                    self.csrf_inside_form = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form_depth > 0:
            self._form_depth -= 1


def _inspect_login(client):
    response = client.get("/ui/login")
    assert response.status_code == 200
    inspector = _LoginFormInspector()
    inspector.feed(response.text)
    return inspector


def test_login_a_un_seul_formulaire(client):
    """Deux <form> = le bug historique. On en veut exactement un."""
    inspector = _inspect_login(client)
    assert inspector.form_count == 1, (
        f"attendu 1 <form>, trouve {inspector.form_count} "
        "(regression du double formulaire de login)"
    )


def test_login_csrf_est_dans_le_formulaire(client):
    """Le token doit etre IMBRIQUE dans le form, pas juste present."""
    inspector = _inspect_login(client)
    assert inspector.csrf_count == 1, (
        f"attendu 1 champ csrf_token, trouve {inspector.csrf_count}"
    )
    assert inspector.csrf_inside_form, (
        "le champ csrf_token existe mais n'est pas dans un <form> : "
        "il ne sera pas soumis par le navigateur"
    )
