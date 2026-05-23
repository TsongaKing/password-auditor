import click
import json
from rich.console import Console
from src.analyzer import analyze_password
from src.display import display_result

console = Console()


@click.group()
def cli():
    pass


@cli.command()
@click.argument('password')
@click.option('--no-breach-check', is_flag=True, help='Skip Have I Been Pwned check')
@click.option('--json-output', is_flag=True, help='Output results as JSON')
def check(password, no_breach_check, json_output):
    check_breach = not no_breach_check
    result = analyze_password(password, check_breach=check_breach)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        display_result(result, password)


@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--no-breach-check', is_flag=True, help='Skip Have I Been Pwned check')
@click.option('--output', default='password_audit.json', help='Output file path')
def audit(file, no_breach_check, output):
    check_breach = not no_breach_check
    results = []

    console.print(f'[dim]Auditing passwords from {file}...[/dim]\n')

    with open(file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for password in passwords:
        result = analyze_password(password, check_breach=check_breach)
        result['password'] = '*' * len(password)
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


if __name__ == '__main__':
    cli()
