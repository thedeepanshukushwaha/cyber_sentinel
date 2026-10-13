"""Report generation dialog for naming and choosing save location."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QMessageBox,
)


class ReportDialog(QDialog):
    """Dialog for configuring report name and save location."""

    def __init__(self, parent=None, target: str = "target", default_dir: Optional[Path] = None) -> None:
        super().__init__(parent)
        self.target = target
        self.default_dir = default_dir or Path.home() / "Downloads"
        self.selected_path: Optional[Path] = None
        self.setWindowTitle("Generate Report")
        self.setGeometry(200, 200, 600, 200)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Report name input
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Report Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., penetration_test_report")
        self.name_input.setText(f"pentest_report_{self.target.replace('.', '_')}")
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)

        # Save location
        location_layout = QHBoxLayout()
        location_layout.addWidget(QLabel("Save Location:"))
        self.location_input = QLineEdit()
        self.location_input.setText(str(self.default_dir))
        self.location_input.setReadOnly(True)
        location_layout.addWidget(self.location_input)

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._on_browse)
        location_layout.addWidget(browse_button)
        layout.addLayout(location_layout)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        generate_button = QPushButton("Generate Report")
        generate_button.clicked.connect(self._on_generate)
        button_layout.addWidget(generate_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _on_browse(self) -> None:
        """Browse for save location."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Choose Report Save Location",
            str(self.location_input.text()),
        )
        if directory:
            self.location_input.setText(directory)

    def _on_generate(self) -> None:
        """Validate and save the selected report path."""
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Invalid Name", "Please enter a report name.")
            return

        location = Path(self.location_input.text().strip())
        if not location.exists():
            QMessageBox.warning(self, "Invalid Location", f"Directory does not exist:\n{location}")
            return

        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        self.selected_path = location / f"{safe_name}.html"

        # Check if file exists
        if self.selected_path.exists():
            response = QMessageBox.question(
                self,
                "File Exists",
                f"Report file already exists:\n{self.selected_path}\n\nOverwrite?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if response != QMessageBox.Yes:
                return

        self.accept()

    def get_report_path(self) -> Optional[Path]:
        """Get the selected report path."""
        return self.selected_path
