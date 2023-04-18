"""This module provides the PyLogAnalyze CLI."""

from pathlib import Path
from typing import Optional
from pyloganalyze import __app_name__, __version__, pyloganalyze

import typer
import json
import pickle
import logging
import pandas as pd
import chardet

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
        help="File containing identifiers to analyze(JSON format).",
    ),
    app_info_file: Path = typer.Argument(
        ...,
        help="csv file containing app info"
    ),
    domain_info_file = typer.Argument(
        ...,
        help="csv file containing domain info"
    ),
    output_folder: Path = typer.Argument(
        ...,
        help="Folder to write the results to.",
    ),
    # input_file: Path = typer.Option(
    #     None,
    #   "--inputdir", "-i",
    #     help="The input file to add results to.",
    #     ),
    ) -> None:
    """Analyze log files of the specified apps."""
    
    typer.echo(f"Analyzing the app logs of the apps listed in {app_file} and writing results to {output_folder}/out.pckl")

    # Create output folder if it doesn't exist
    if not output_folder.exists():
        output_folder.mkdir(parents=True)
    #os.chdir(output_folder)

    # Create logging
    logging.basicConfig(filename=(str(output_folder)+"/debug.log"), level=logging.DEBUG)


    primaryfiles_paths = []

    try:
        with open(app_file, 'r') as file:
            primaryfiles_paths = [Path(x.strip()) for x in file.readlines()]  
    except FileNotFoundError as e:
        logging.error(f"Error Opening App Paths File: {e}")
        raise typer.Exit(1)

    identifier_dict = {}

    try:
        with open(identifier_file, 'r') as file:
            try:
                identifier_dict = json.load(file)
            except json.JSONDecodeError as e:
                logging.error(f"Error Loading Identifier Dictionary: {e}")
                raise typer.Exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error Opening Identifier Dictionary: {e}")
        raise typer.Exit(1)

    appInfo = pd.read_csv(app_info_file)
    domainInfo = pd.read_csv(domain_info_file)

    # Init the controller
    # TODO decide if we should check for an  existing analysis file
    controller = pyloganalyze.PyLogAnalyze(appfile=primaryfiles_paths, identifierdict=identifier_dict, appinfo=appInfo, domaininfo=domainInfo)

    # Analyze the log files
    controller.Analyze()

    # Save the results
    try:
        with open(str(output_folder)+"/out.pkl", 'wb') as outp:  # Overwrites any existing file.
            try:
                pickle.dump(controller, outp, pickle.HIGHEST_PROTOCOL)
            except pickle.PickleError as e:
                logging.error(f"Error Writing Results Object to Pickle File: {e}")
                raise typer.Exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error Opening Results File: {e}")
        raise typer.Exit(1)


@app.command()
def csv(
    input_file: Path = typer.Argument(
        ...,
        help="File path containing the results to analyze.",
    ),
    output_folder: Path = typer.Argument(
        ...,
        help="The output folder to put the results into.",
    ),
) -> None:
    """Produce a CSV file from the results"""

    # Check if output folder exists
    if not output_folder.exists():
        logging.error(f"Output Folder doesn't Exist")
        raise typer.Exit(1)

    print(f"Writing results from {input_file} into {output_folder} as out.csv")
    logging.basicConfig(filename=(str(output_folder)+'/debug.log'), level=logging.DEBUG)


    # Init the controller
    try:
        with open(str(input_file), 'rb') as inp:
            try:
                controller =  pickle.load(inp)
            except pickle.PickleError as e:
                logging.error(f"Error Loading Results Object: {e}")
                raise typer.Exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error Opening Results Object: {e}")
        raise typer.Exit(1)
    
    # Save the results

    dfapp, dfdomain = controller.ToDataFrame()
    dfapp.to_csv(str(output_folder)+"/outApp.csv", index=0)
    dfdomain.to_csv(str(output_folder)+"/outDomain.csv", index=0)


@app.command()
def thirdparty(
    input_file: Path = typer.Argument(
        ...,
        help="File path containing the results to analyze.",
    ),
    output_folder: Path = typer.Argument(
        ...,
        help="The output folder to put the results into.",
    ),
) -> None:
    """Analyze results."""
    
    # Check if output folder exists
    if not output_folder.exists():
        logging.error(f"Output Folder doesn't Exist")
        raise typer.Exit(1)

    typer.echo(f"Analyzing results from {input_file} and writing to {output_folder}/out.json")
    logging.basicConfig(filename=str(output_folder)+'/debug.log', level=logging.DEBUG)

    # Init the controller
    try:
        with open(str(input_file), 'rb') as inp:
            try:
                controller = pickle.load(inp)
            except pickle.PickleError as e:
                logging.error(f"Error Loading Results Object: {e}")
                raise typer.Exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error Opening Results Object: {e}")
        raise typer.Exit(1)
    
    us_full, us_nonfull, nonus_full, nonus_nonfull = controller.ThirdParty()

    # create json object from dictionary
    statsJson = json.dumps(us_full, indent=2)
    # open file for writing, "w" 
    f = open(str(output_folder)+"/us_full.json","w")
    # write json object to file
    f.write(statsJson)
    # close file
    f.close()

    # create json object from dictionary
    statsJson = json.dumps(us_nonfull, indent=2)
    # open file for writing, "w" 
    f = open(str(output_folder)+"/us_nonfull.json","w")
    # write json object to file
    f.write(statsJson)
    # close file
    f.close()

    # create json object from dictionary
    statsJson = json.dumps(nonus_full, indent=2)
    # open file for writing, "w" 
    f = open(str(output_folder)+"/nonus_full.json","w")
    # write json object to file
    f.write(statsJson)
    # close file
    f.close()
    
    # create json object from dictionary
    statsJson = json.dumps(nonus_nonfull, indent=2)
    # open file for writing, "w" 
    f = open(str(output_folder)+"/nonus_nonfull.json","w")
    # write json object to file
    f.write(statsJson)
    # close file
    f.close()