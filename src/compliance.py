NIST_800_63B = {
    'min_length': 8,
    'recommended_length': 15,
    'max_length': 64,
    'allow_spaces': True,
    'allow_unicode': True,
    'breach_check_required': True,
}


def check_nist_compliance(result: dict) -> dict:
    issues = []
    passed = []

    length = result['password_length']

    if length < NIST_800_63B['min_length']:
        issues.append(f'Length {length} is below NIST minimum of {NIST_800_63B["min_length"]}')
    else:
        passed.append(f'Length {length} meets NIST minimum of {NIST_800_63B["min_length"]}')

    if length >= NIST_800_63B['recommended_length']:
        passed.append(f'Length meets NIST recommended length of {NIST_800_63B["recommended_length"]}+')
    else:
        issues.append(f'NIST recommends at least {NIST_800_63B["recommended_length"]} characters')

    if result['is_breached']:
        issues.append('Password found in breach database - fails NIST breach check requirement')
    else:
        passed.append('Not found in known breach databases')

    if result['score'] < 2:
        issues.append('Password entropy too low for NIST compliance')
    else:
        passed.append('Password entropy meets NIST guidelines')

    compliant = len(issues) == 0

    return {
        'standard': 'NIST SP 800-63B',
        'compliant': compliant,
        'status': 'PASS' if compliant else 'FAIL',
        'issues': issues,
        'passed': passed
    }
