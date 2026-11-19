"""
CryptoShield — Real-time Threat Gauge Component (Phase 10)
Displays dynamic 0–100 threat scoring with color-coded severity levels and progress bar.
"""

from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import ThemeColors, get_severity_bg, get_severity_color


class ThreatGauge(QFrame):
    """
    SOC threat gauge showing current numerical threat score (0–100),
    severity badge (NORMAL, LOW, MEDIUM, HIGH, CRITICAL), and progress meter.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.score: int = 0
        self.severity: str = "NORMAL"

        self.setObjectName("threat-gauge")
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumHeight(115)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        # Header: Title + Severity Badge
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        lbl_title = QLabel("CURRENT THREAT ASSESSMENT")
        lbl_title.setStyleSheet(f"""
            color: {ThemeColors.TEXT_SECONDARY};
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        """)
        header_layout.addWidget(lbl_title)
        header_layout.addStretch()

        self.badge_severity = QLabel("NORMAL")
        self.badge_severity.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(self.badge_severity)
        layout.addLayout(header_layout)

        # Score Row
        score_layout = QHBoxLayout()
        self.lbl_score = QLabel("0 / 100")
        self.lbl_score.setStyleSheet(f"""
            color: {ThemeColors.TEXT_PRIMARY};
            font-size: 28px;
            font-weight: 900;
        """)
        score_layout.addWidget(self.lbl_score)

        self.lbl_description = QLabel("No suspicious ransomware or exfiltration indicators")
        self.lbl_description.setStyleSheet(f"""
            color: {ThemeColors.TEXT_MUTED};
            font-size: 12px;
        """)
        score_layout.addWidget(self.lbl_description, 1)
        layout.addLayout(score_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        layout.addWidget(self.progress_bar)

        self.set_threat(0, "NORMAL")

    def set_threat(self, score: int, severity: Optional[str] = None) -> None:
        """Update threat meter score and styling."""
        self.score = max(0, min(100, int(score)))

        if not severity:
            if self.score >= 85:
                severity = "CRITICAL"
            elif self.score >= 60:
                severity = "HIGH"
            elif self.score >= 35:
                severity = "MEDIUM"
            elif self.score > 0:
                severity = "LOW"
            else:
                severity = "NORMAL"

        self.severity = severity.upper()
        color = get_severity_color(self.severity)
        bg = get_severity_bg(self.severity)

        self.lbl_score.setText(f"{self.score} / 100")
        self.lbl_score.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: 900;")

        self.badge_severity.setText(self.severity)
        self.badge_severity.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {bg};
                border: 1px solid {color};
                border-radius: 10px;
                padding: 3px 12px;
                font-size: 11px;
                font-weight: 800;
            }}
        """)

        # Update description text
        if self.severity == "CRITICAL":
            desc = "IMMINENT RANSOMWARE ENCRYPTION / CONTAINMENT REQUIRED"
        elif self.severity == "HIGH":
            desc = "Active attack indicators or canary honeypot breach detected"
        elif self.severity == "MEDIUM":
            desc = "Elevated burst activity or unauthorized staging detected"
        elif self.severity == "LOW":
            desc = "Mild telemetry anomaly observed across laboratory files"
        else:
            desc = "All telemetry sensors nominal; baseline fully protected"
        self.lbl_description.setText(desc)

        # Update progress bar
        self.progress_bar.setValue(self.score)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {ThemeColors.BG_INPUT};
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)

        # Container border accent
        self.setStyleSheet(f"""
            QFrame#threat-gauge {{
                background-color: {ThemeColors.BG_CARD};
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-left: 4px solid {color};
                border-radius: 6px;
            }}
        """)
