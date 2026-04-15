"""Entry point shim so `python -m recomet` and `recomet` CLI both work."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recomet.core import *

def main():
    # Import and call the full CLI
    import importlib.util, os
    cli_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recomet.py")
    spec = importlib.util.spec_from_file_location("cli", cli_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
