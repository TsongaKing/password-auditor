import secrets
import string


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in '!@#$%^&*' for c in password)):
            return password


def generate_passphrase(words: int = 4) -> str:
    wordlist = [
        'correct', 'horse', 'battery', 'staple', 'river', 'mountain',
        'sunset', 'cloud', 'forest', 'ocean', 'thunder', 'silver',
        'dragon', 'castle', 'bridge', 'lantern', 'winter', 'garden',
        'crystal', 'falcon', 'anchor', 'compass', 'eagle', 'marble',
        'pepper', 'rocket', 'shadow', 'tunnel', 'viking', 'wizard'
    ]
    return '-'.join(secrets.choice(wordlist) for _ in range(words))
