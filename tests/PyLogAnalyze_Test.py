
from typer.testing import CliRunner

from pyloganalyze import __app_name__, __version__, cli

runner = CliRunner()

def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert f"{__app_name__} v{__version__}\n" in result.stdout

def test_analyze():
    # TODO bulk this test up
    result = runner.invoke(cli.app, ["analyze", "tests/apps", "tests/identifiers.json"])
    assert result.exit_code == 0
    assert "Analyzing app logs from tests/apps and writing results to None" in result.stdout