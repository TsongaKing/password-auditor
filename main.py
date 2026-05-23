import click
import json
from rich.console import Console
from rich.table import Table
from src.analyzer import analyze_password
from src.display import display_result
from src.generator import generate_password, generate_passphrase
from src.compliance import check_nist_compliance

console = Console()


@click.group()
def cli():
    pass


@cli.command()
@click.argument('password')
@click.option('--no-breach-check', is_flag=True, help='Skip Have I Been Pwned check')
@click.option('--json-output', is_flag=True, help='Output results as JSON')
@click.option('--compliance', is_flag=True, help='Show NIST SP 800-63B compliance')
def check(password, no_breach_check, json_output, compliance):
    check_breach = not no_breach_check
    result = analyze_password(password, check_breach=check_breach)

    if compliance:
        result['compliance'] = check_nist_compliance(result)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        display_result(result, password)
        if compliance:
            show_compliance(result['compliance'])


@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--no-breach-check', is_flag=True, help='Skip Have I Been Pwned check')
@click.option('--output', default='password_audit.json', help='Output file path')
@click.option('--compliance', is_flag=True, help='Show NIST SP 800-63B compliance')
def audit(file, no_breach_check, output, compliance):
    check_breach = not no_breach_check
    results = []

    console.print(f'[dim]Auditing passwords from {file}...[/dim]\n')

    with open(file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for password in passwords:
        result = analyze_password(password, check_breach=check_breach)
        result['password'] = '*' * len(password)
        if compliance:
            result['compliance'] = check_nist_compliance(result)
        results.append(result)
        display_result(result)

    weak = [r for r in results if r['score'] < 2]
    breached = [r for r in results if r['is_breached']]

    console.print('[bold]Audit Summary:[/bold]')
    console.print(f'  Total passwords: {len(results)}')
    console.print(f'  Weak passwords: [red]{len(weak)}[/red]')
    console.print(f'  Breached passwords: [red]{len(breached)}[/red]')

    with open(output, 'w') as f:
        json.dump(results, f, indent=2)

    console.print(f'\n[dim]Full results saved to {output}[/dim]')


@cli.command()
@click.option('--length', default=16, help='Password length')
@click.option('--type', 'pwd_type', default='password', type=click.Choice(['password', 'passphrase']), help='Type to generate')
@click.option('--words', default=4, help='Number of words for passphrase')
@click.option('--count', default=1, help='Number of passwords to generate')
def generate(length, pwd_type, words, count):
    console.print('[bold]Generated Passwords:[/bold]\n')
    for i in range(count):
        if pwd_type == 'passphrase':
            pwd = generate_passphrase(words)
            console.print(f'  [green]{pwd}[/green] [dim](passphrase - NIST recommended)[/dim]')
        else:
            pwd = generate_password(length)
            console.print(f'  [green]{pwd}[/green]')
    console.print()


def show_compliance(compliance: dict):
    status_color = 'green' if compliance['compliant'] else 'red'
    console.print(f'\n[bold]Compliance: {compliance["standard"]}[/bold]')
    console.print(f'Status: [{status_color}]{compliance["status"]}[/{status_color}]\n')

    if compliance['passed']:
        for item in compliance['passed']:
            console.print(f'  [green]PASS[/green] {item}')

    if compliance['issues']:
        for item in compliance['issues']:
            console.print(f'  [red]FAIL[/red] {item}')
    console.print()


if __name__ == '__main__':
    cli()
