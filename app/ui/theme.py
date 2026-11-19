"""
CryptoShield — SOC Dark Theme & Visual Styling Specification (Phase 10)
Provides modern cybersecurity dashboard styling, color palettes, and styling utilities.
"""

from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout, QWidget


# -----------------------------------------------------------------------------
# Color Palette Constants
# -----------------------------------------------------------------------------
class ThemeColors:
    # Backgrounds
    BG_ROOT = "#0b0f19"          # Deep obsidian black-blue
    BG_CARD = "#131b2e"          # Surface / panel background
    BG_CARD_ALT = "#18233c"      # Slightly elevated surface
    BG_INPUT = "#1a2540"         # Form input & table row background
    BG_HOVER = "#243254"         # Hover state

    # Borders & Dividers
    BORDER_DEFAULT = "#223150"
    BORDER_FOCUSED = "#3b82f6"
    BORDER_MUTED = "#17233a"

    # Typography
    TEXT_PRIMARY = "#f8fafc"     # High-contrast white
    TEXT_SECONDARY = "#94a3b8"   # Muted slate gray
    TEXT_MUTED = "#64748b"       # Subdued caption
    TEXT_ACCENT = "#38bdf8"      # Light cyan

    # Semantic Status Accents
    GREEN = "#10b981"            # Clean / Intact / Verified / 0 Bytes Leaked
    GREEN_BG = "#064e3b"
    CYAN = "#06b6d4"             # Active / Telemetry / Info
    CYAN_BG = "#164e63"
    BLUE = "#3b82f6"             # Primary actions
    BLUE_BG = "#1e3a8a"
    AMBER = "#f59e0b"            # Medium Threat / Quarantined / Warning
    AMBER_BG = "#78350f"
    ORANGE = "#f97316"           # High Threat / Canary Honeypot Breached
    ORANGE_BG = "#7c2d12"
    RED = "#ef4444"              # Critical Threat / Containment Active / Blocked
    RED_BG = "#7f1d1d"
    PURPLE = "#8b5cf6"           # Cryptographic Vault / RSA-3072 / Argon2id
    PURPLE_BG = "#4c1d95"


# -----------------------------------------------------------------------------
# Global Qt Style Sheet (QSS)
# -----------------------------------------------------------------------------
SOC_DARK_THEME_QSS = f"""
QMainWindow, QDialog {{
    background-color: {ThemeColors.BG_ROOT};
    color: {ThemeColors.TEXT_PRIMARY};
}}

QWidget {{
    background-color: transparent;
    color: {ThemeColors.TEXT_PRIMARY};
    font-family: "Segoe UI", "Inter", -apple-system, sans-serif;
    font-size: 13px;
}}

/* Top Navigation / Tab Bar */
QTabWidget::pane {{
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    background-color: {ThemeColors.BG_CARD};
    border-radius: 6px;
    top: -1px;
}}

QTabBar::tab {{
    background-color: {ThemeColors.BG_ROOT};
    color: {ThemeColors.TEXT_SECONDARY};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}}

QTabBar::tab:selected {{
    background-color: {ThemeColors.BG_CARD};
    color: {ThemeColors.TEXT_ACCENT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-bottom: 2px solid {ThemeColors.CYAN};
}}

QTabBar::tab:hover:!selected {{
    background-color: {ThemeColors.BG_CARD_ALT};
    color: {ThemeColors.TEXT_PRIMARY};
}}

/* Group Boxes / Panels */
QGroupBox {{
    background-color: {ThemeColors.BG_CARD};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 8px;
    margin-top: 22px;
    padding: 14px 12px 12px 12px;
    font-weight: 700;
    color: {ThemeColors.TEXT_ACCENT};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 2px 10px;
    background-color: {ThemeColors.BG_CARD_ALT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 4px;
    color: {ThemeColors.TEXT_ACCENT};
    left: 12px;
}}

/* Push Buttons */
QPushButton {{
    background-color: {ThemeColors.BG_INPUT};
    color: {ThemeColors.TEXT_PRIMARY};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 5px;
    padding: 7px 15px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {ThemeColors.BG_HOVER};
    border-color: {ThemeColors.BORDER_FOCUSED};
}}

QPushButton:pressed {{
    background-color: {ThemeColors.BORDER_DEFAULT};
}}

QPushButton:disabled {{
    background-color: {ThemeColors.BG_CARD};
    color: {ThemeColors.TEXT_MUTED};
    border-color: {ThemeColors.BORDER_MUTED};
}}

QPushButton#btn-primary {{
    background-color: {ThemeColors.BLUE_BG};
    color: #ffffff;
    border: 1px solid {ThemeColors.BLUE};
}}

QPushButton#btn-primary:hover {{
    background-color: #2563eb;
}}

QPushButton#btn-danger {{
    background-color: {ThemeColors.RED_BG};
    color: #ffffff;
    border: 1px solid {ThemeColors.RED};
}}

QPushButton#btn-danger:hover {{
    background-color: #dc2626;
}}

QPushButton#btn-success {{
    background-color: {ThemeColors.GREEN_BG};
    color: #ffffff;
    border: 1px solid {ThemeColors.GREEN};
}}

QPushButton#btn-success:hover {{
    background-color: #059669;
}}

/* Inputs & Form Controls */
QLineEdit, QSpinBox, QComboBox {{
    background-color: {ThemeColors.BG_INPUT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 5px;
    padding: 6px 10px;
    color: {ThemeColors.TEXT_PRIMARY};
    selection-background-color: {ThemeColors.BLUE};
}}

QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {ThemeColors.BORDER_FOCUSED};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background-color: {ThemeColors.BG_CARD_ALT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    selection-background-color: {ThemeColors.BG_HOVER};
    color: {ThemeColors.TEXT_PRIMARY};
}}

/* Tables */
QTableWidget {{
    background-color: {ThemeColors.BG_CARD};
    alternate-background-color: {ThemeColors.BG_CARD_ALT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 6px;
    gridline-color: {ThemeColors.BORDER_MUTED};
    color: {ThemeColors.TEXT_PRIMARY};
    selection-background-color: {ThemeColors.BG_HOVER};
    selection-color: {ThemeColors.TEXT_PRIMARY};
}}

QHeaderView::section {{
    background-color: {ThemeColors.BG_ROOT};
    color: {ThemeColors.TEXT_SECONDARY};
    padding: 6px;
    font-weight: 700;
    border: none;
    border-bottom: 2px solid {ThemeColors.BORDER_DEFAULT};
    border-right: 1px solid {ThemeColors.BORDER_MUTED};
}}

/* Progress Bar */
QProgressBar {{
    background-color: {ThemeColors.BG_INPUT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 4px;
    text-align: center;
    color: {ThemeColors.TEXT_PRIMARY};
    font-weight: 600;
    height: 18px;
}}

QProgressBar::chunk {{
    background-color: {ThemeColors.CYAN};
    border-radius: 3px;
}}

/* Scroll Bars */
QScrollBar:vertical {{
    background-color: {ThemeColors.BG_ROOT};
    width: 10px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background-color: {ThemeColors.BORDER_DEFAULT};
    min-height: 20px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {ThemeColors.BORDER_FOCUSED};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* Text Log / Console */
QTextEdit {{
    background-color: {ThemeColors.BG_ROOT};
    border: 1px solid {ThemeColors.BORDER_DEFAULT};
    border-radius: 6px;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    color: #e2e8f0;
    padding: 8px;
}}

/* Status Bar */
QStatusBar {{
    background-color: {ThemeColors.BG_ROOT};
    border-top: 1px solid {ThemeColors.BORDER_DEFAULT};
    color: {ThemeColors.TEXT_SECONDARY};
}}
"""


# -----------------------------------------------------------------------------
# Styling Utility Helpers
# -----------------------------------------------------------------------------
def get_severity_color(severity: str) -> str:
    """Map threat severity strings to standard palette hex codes."""
    s = (severity or "").upper().strip()
    if s == "CRITICAL":
        return ThemeColors.RED
    elif s == "HIGH":
        return ThemeColors.ORANGE
    elif s == "MEDIUM":
        return ThemeColors.AMBER
    elif s == "LOW":
        return ThemeColors.CYAN
    return ThemeColors.GREEN


def get_severity_bg(severity: str) -> str:
    """Map threat severity strings to subtle background fill hex codes."""
    s = (severity or "").upper().strip()
    if s == "CRITICAL":
        return ThemeColors.RED_BG
    elif s == "HIGH":
        return ThemeColors.ORANGE_BG
    elif s == "MEDIUM":
        return ThemeColors.AMBER_BG
    elif s == "LOW":
        return ThemeColors.CYAN_BG
    return ThemeColors.GREEN_BG


def create_status_badge(text: str, color_hex: str, bg_hex: Optional[str] = None) -> QLabel:
    """Create a stylized pill badge for status indicators."""
    badge = QLabel(text)
    badge.setAlignment(Qt.AlignCenter)
    bg = bg_hex if bg_hex else ThemeColors.BG_CARD_ALT
    badge.setStyleSheet(f"""
        QLabel {{
            color: {color_hex};
            background-color: {bg};
            border: 1px solid {color_hex};
            border-radius: 10px;
            padding: 3px 10px;
            font-size: 11px;
            font-weight: 700;
        }}
    """)
    return badge


def create_section_header(title: str, subtitle: Optional[str] = None) -> QWidget:
    """Create a consistent typography header with optional subtitle."""
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 8)
    layout.setSpacing(2)

    lbl_title = QLabel(title)
    lbl_title.setStyleSheet(f"""
        color: {ThemeColors.TEXT_PRIMARY};
        font-size: 17px;
        font-weight: 700;
    """)
    layout.addWidget(lbl_title)

    if subtitle:
        lbl_sub = QLabel(subtitle)
        lbl_sub.setStyleSheet(f"""
            color: {ThemeColors.TEXT_SECONDARY};
            font-size: 12px;
        """)
        layout.addWidget(lbl_sub)

    return container


def apply_soc_theme(app_or_widget) -> None:
    """Apply the global CryptoShield SOC dark stylesheet to a QApplication or QWidget."""
    app_or_widget.setStyleSheet(SOC_DARK_THEME_QSS)
