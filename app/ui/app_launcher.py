"""
CryptoShield — GUI Desktop Application Launcher (Phase 10)
Configures display scaling, initializes the Qt event loop, applies the SOC theme,
and launches the CryptoShieldMainWindow.
"""

import os
import sys
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.config import CONFIG
from app.core.logger import get_logger
from app.ui.bridge import EventBusBridge
from app.ui.main_window import CryptoShieldMainWindow
from app.ui.theme import apply_soc_theme

logger = get_logger("ui.launcher")


def launch_gui(args: Optional[List[str]] = None, offscreen: bool = False) -> int:
    """
    Primary entry point to launch the CryptoShield PySide6 Desktop GUI.

    Args:
        args: Command-line arguments passed to QApplication.
        offscreen: If True, runs Qt in headless offscreen mode without physical display.

    Returns:
        Exit code from the Qt application event loop.
    """
    CONFIG.ensure_directories()
    raw_args = args or sys.argv

    # Support headless execution for automated testing or non-GUI environments
    if offscreen or "--offscreen" in raw_args:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        logger.info("Starting CryptoShield GUI in headless offscreen mode.")

    app = QApplication.instance()
    if app is None:
        app = QApplication(raw_args)

    # Application Branding Metadata
    app.setApplicationName("CryptoShield")
    app.setApplicationDisplayName("CryptoShield Defensive Framework")
    app.setOrganizationName("NFSU")
    app.setOrganizationDomain("nfsu.ac.in")

    # Apply SOC Dark Stylesheet
    apply_soc_theme(app)

    # Initialize EventBus Bridge
    bridge = EventBusBridge()
    bridge.connect_bus()

    # Launch Main Window
    window = CryptoShieldMainWindow(bridge=bridge)
    window.show()
    logger.info("CryptoShield Desktop GUI successfully initialized.")

    # In offscreen mode when running programmatically without blocking loop, process events and exit cleanly
    if offscreen or "--offscreen" in raw_args:
        app.processEvents()
        logger.info("Headless verification completed; exiting cleanly.")
        return 0

    return app.exec()
