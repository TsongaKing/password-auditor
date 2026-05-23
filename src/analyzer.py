import re
import hashlib
import requests
from zxcvbn import zxcvbn


def check_haveibeenpwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        response = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            timeout=5,
            headers={'User-Agent': 'password-auditor-security-tool'}
        )
        if response.status_code == 200:
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return int(count)
    except Exception:
        return -1
    return 0


def detect_patterns(password: str) -> list:
    patterns = []

    keyboard_walks = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'qweasd', 'qazwsx']
    for walk in keyboard_walks:
        if walk.lower() in password.lower():
            patterns.append(f'keyboard_walk: {walk}')

    if re.search(r'(.)\1{2,}', password):
        patterns.append('repeated_characters')

    if re.search(r'\b(19|20)\d{2}\b', password):
        patterns.append('contains_year')

    if re.search(r'\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2,4}\b', password):
        patterns.append('contains_date')

    if re.search(r'^[a-zA-Z]+\d+$', password) or re.search(r'^\d+[a-zA-Z]+$', password):
        patterns.append('word_plus_numbers')

    if re.search(r'password|passwd|pass|secret|admin|login', password, re.IGNORECASE):
        patterns.append('contains_common_word')

    return patterns


def analyze_password(password: str, check_breach: bool = True) -> dict:
    result = zxcvbn(password)

    score = result['score']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    suggestions = result['feedback']['suggestions']
    warning = result['feedback']['warning']

    patterns = detect_patterns(password)

    breach_count = 0
    if check_breach:
        breach_count = check_haveibeenpwned(password)

    strength_labels = {
        0: 'Very Weak',
        1: 'Weak',
        2: 'Fair',
        3: 'Strong',
        4: 'Very Strong'
    }

    strength_colors = {
        0: 'red',
        1: 'red',
        2: 'yellow',
        3: 'green',
        4: 'bright_green'
    }

    return {
        'password_length': len(password),
        'score': score,
        'strength': strength_labels[score],
        'strength_color': strength_colors[score],
        'crack_time': crack_time,
        'warning': warning,
        'suggestions': suggestions,
        'patterns_detected': patterns,
        'breach_count': breach_count,
        'is_breached': breach_count > 0,
        'recommendations': build_recommendations(score, patterns, breach_count)
    }


def build_recommendations(score: int, patterns: list, breach_count: int) -> list:
    recs = []

    if breach_count > 0:
        recs.append(f'CRITICAL: This password has appeared in {breach_count:,} data breaches. Change it immediately.')

    if score < 2:
        recs.append('Use at least 12 characters combining uppercase, lowercase, numbers and symbols.')

    if 'keyboard_walk' in str(patterns):
        recs.append('Avoid keyboard patterns like qwerty or 123456.')

    if 'repeated_characters' in patterns:
        recs.append('Avoid repeated characters like aaa or 111.')

    if 'contains_year' in patterns or 'contains_date' in patterns:
        recs.append('Avoid using dates or years in passwords.')

    if 'word_plus_numbers' in patterns:
        recs.append('Avoid simple word+number combinations like password123.')

    if 'contains_common_word' in patterns:
        recs.append('Avoid using common words like password, admin, or secret.')

    if score >= 3 and breach_count == 0:
        recs.append('Good password! Consider using a password manager to store it securely.')

    return recs
