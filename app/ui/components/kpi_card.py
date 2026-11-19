"""
CryptoShield — SOC Metric KPI Card (Phase 10)
Reusable dashboard card for presenting prominent security metrics and operational states.
"""

from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from app.ui.theme import ThemeColors


class KPICard(QFrame):
    """
    A stylized SOC metric card with an accent indicator, prominent value label,
    and descriptive subtitle.
    """

    def __init__(
        self,
        title: str,
        initial_value: str = "—",
        subtitle: str = "",
        accent_color: str = ThemeColors.CYAN,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.accent_color = accent_color

        self.setObjectName("kpi-card")
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumHeight(105)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        # Title / Metric Category
        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet(f"""
            QLabel {{
                color: {ThemeColors.TEXT_SECONDARY};
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
        """)
        layout.addWidget(self.lbl_title)

        # Primary Large Value
        self.lbl_value = QLabel(initial_value)
        self.lbl_value.setStyleSheet(f"""
            QLabel {{
                color: {ThemeColors.TEXT_PRIMARY};
                font-size: 24px;
                font-weight: 800;
                font-family: "Segoe UI", sans-serif;
            }}
        """)
        layout.addWidget(self.lbl_value)

        # Subtitle / Details
        self.lbl_subtitle = QLabel(subtitle)
        self.lbl_subtitle.setStyleSheet(f"""
            QLabel {{
                color: {ThemeColors.TEXT_MUTED};
                font-size: 11px;
            }}
        """)
        layout.addWidget(self.lbl_subtitle)

        self._update_border()

    def _update_border(self) -> None:
        """Applies dynamic border color styling based on accent_color."""
        self.setStyleSheet(f"""
            QFrame#kpi-card {{
                background-color: {ThemeColors.BG_CARD};
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-left: 4px solid {self.accent_color};
                border-radius: 6px;
            }}
        """)

    def set_value(self, value: str, accent_color: Optional[str] = None) -> None:
        """Updates the primary value and optional accent color."""
        self.lbl_value.setText(str(value))
        if accent_color and accent_color != self.accent_color:
            self.accent_color = accent_color
            self._update_border()

    def set_subtitle(self, subtitle: str) -> None:
        """Updates the context description."""
        self.lbl_subtitle.setText(subtitle)

    def set_accent_color(self, accent_color: str) -> None:
        """Updates the accent color and refreshes the border."""
        self.accent_color = accent_color
        self._update_border()
