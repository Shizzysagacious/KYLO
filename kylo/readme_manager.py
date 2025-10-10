import os
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from .utils import load_json, save_json

console = Console()

README_TEMPLATE = """# {project_name}

## Project Goals
{goals}

## Technologies
{technologies}

## Security Requirements
{security}

## Additional Notes
{notes}
"""

def create_readme_interactive(path):
    """Interactive README creation with rich UI"""
    console.print("[bold blue]Welcome to Kylo README Creator[/bold blue]")
    console.print("Let's define your project goals and requirements.\n")

    project_name = Prompt.ask("[bold]Project name", default=os.path.basename(os.path.dirname(path)))
    
    console.print("\n[bold yellow]Project Goals[/bold yellow]")
    console.print("Describe the main objectives of your project. These will be used to validate code alignment.")
    goals = Prompt.ask("Goals")

    console.print("\n[bold yellow]Technologies[/bold yellow]")
    console.print("List main technologies, frameworks, and languages used.")
    technologies = Prompt.ask("Technologies")

    console.print("\n[bold yellow]Security Requirements[/bold yellow]")
    console.print("Define security requirements and compliance needs.")
    security = Prompt.ask("Security requirements")

    console.print("\n[bold yellow]Additional Notes[/bold yellow]")
    notes = Prompt.ask("Notes", default="")

    readme_content = README_TEMPLATE.format(
        project_name=project_name,
        goals=goals,
        technologies=technologies,
        security=security,
        notes=notes
    )

    # Save both the README and structured goals
    with open(path, 'w', encoding='utf-8') as f:
        f.write(readme_content)

    goals_data = {
        "project_name": project_name,
        "goals": goals.split('\n'),
        "technologies": technologies.split(','),
        "security_requirements": security.split('\n'),
        "notes": notes,
        "version": "1.0.0"
    }

    state_dir = os.path.join(os.path.dirname(path), '.kylo')
    os.makedirs(state_dir, exist_ok=True)
    save_json(os.path.join(state_dir, 'goals.json'), goals_data)

    console.print("\n[bold green]✓[/bold green] README.md created successfully!")
    console.print("[bold green]✓[/bold green] Project goals saved to .kylo/goals.json")
    
    # Preview the README
    console.print("\n[bold]Preview of your README.md:[/bold]")
    console.print(Panel(Markdown(readme_content), title="README.md", border_style="blue"))

    return goals_data