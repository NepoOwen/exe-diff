import os
import sys

LIB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "port-ida-database", "lib"))
if LIB not in sys.path:
    sys.path.insert(0, LIB)
