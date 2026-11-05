"""
IoTGuard Application Root Launcher
Runs the complete IoTGuard Stage-Aware IDS Dashboard with the Humanised Theme.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Execute the IoTGuard Dashboard application
import dashboard.app
