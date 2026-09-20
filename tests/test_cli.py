import pytest
from unittest.mock import patch
from clawkit.cli import main

def test_cli_help():
    with patch("sys.argv", ["clawkit", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
