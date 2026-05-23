from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


def display_result(result: dict, password: str = ''):
    score = result['score']
    strength = result['strength']
    color = result['strength_color']

    console.print(Panel.fit(
        f'[bold {color}]{strength}[/bold {color}] - Score: {score}/4',
        title='Password Strength',
        border_style=color
    ))

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column('Field', style='dim', width=20)
    table.add_column('Value')

    table.add_row('Length', str(result['password_length']))
    table.add_row('Crack Time', result['crack_time'])

    if result['warning']:
        table.add_row('Warning', f'[yellow]{result["warning"]}[/yellow]')

    if result['is_breached']:
        table.add_row(
            'Breach Status',
            f'[red]COMPROMISED - Found in {result["breach_count"]:,} breaches[/red]'
        )
    elif result['breach_count'] == 0:
        table.add_row('Breach Status', '[green]Not found in known breaches[/green]')
    else:
        table.add_row('Breach Status', '[dim]Check unavailable[/dim]')

    if result['patterns_detected']:
        table.add_row('Patterns', f'[yellow]{", ".join(result["patterns_detected"])}[/yellow]')

    console.print(table)

    if result['recommendations']:
        console.print('\n[bold]Recommendations:[/bold]')
        for rec in result['recommendations']:
            icon = '[red]![/red]' if 'CRITICAL' in rec else '[yellow]*[/yellow]'
            console.print(f'  {icon} {rec}')

    console.print()
