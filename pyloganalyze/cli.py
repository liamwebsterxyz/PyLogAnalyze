"""This module provides the PyLogAnalyze CLI."""

from pathlib import Path
from typing import Optional
from pyloganalyze import __app_name__, __version__, pyloganalyze

import typer
import json


app = typer.Typer()

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    )
) -> None:
    return

@app.command()
def analyze(
    app_file: str = typer.Argument(
        ...,
        help="File containing absolute paths to app folders, one per line.",
    ),
    identifier_file: Path = typer.Argument(
        ..., 
        help="File containing identifiers to analyze(JSON format).",),
    input_file: Path = typer.Option(
        None,
      "--inputdir", "-i",
        help="The input file to add results to.",
        ),
    output_file: Path = typer.Option(
        None,
        "--outputdir", "-d",
        help="The output file to write the results to.",
    ),
) -> None:
    """Analyze log files."""

    typer.echo(f"Analyzing app logs from {app_file} and writing results to {output_file}.")

    primaryfiles_paths = []

    try:
        with open(app_file, 'r') as file:
            primaryfiles_paths = [Path(x.strip()) for x in file.readlines()]  
    except FileNotFoundError as e:
        typer.echo(f"Error Opening File Paths: {e}")
        raise typer.Exit(1)

    identifier_dict = {}

    try:
        with open(identifier_file, 'r') as file:
            try:
                identifier_dict = json.load(file)
            except json.JSONDecodeError as e:
                typer.echo(f"Error Loading Identifier Dictionary: {e}")
                raise typer.Exit(1)
    except FileNotFoundError as e:
        typer.echo(f"Error Opening Identifier Dictionary: {e}")
        raise typer.Exit(1)

    # Init the controller
    controller = pyloganalyze.PyLogAnalyze(primaryfiles_paths, identifier_dict, input_file, output_file)

    # Analyze the log files
    controller.Analyze()

    # TODO call other functions ie add analysis options
    controller.GetStats()
    # Save the results
    # TODO finish this
    #controller.Save()

