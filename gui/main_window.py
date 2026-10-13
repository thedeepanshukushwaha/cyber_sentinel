"""Main window for the Automated Penetration Testing Toolkit GUI."""

from __future__ import annotations

from pathlib import Path

from PyQt5.QtWidgets import QApplication, QMainWindow

from .guided_mode import GuidedModeWidget


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CyberSentinel Toolkit")
        self.resize(1280, 900)
        self.setCentralWidget(GuidedModeWidget())
        self._apply_stylesheet()

    def _apply_stylesheet(self) -> None:
        stylesheet_path = Path(__file__).resolve().parent / "style.qss"
        if stylesheet_path.exists():
            with stylesheet_path.open("r", encoding="utf-8") as handle:
                self.setStyleSheet(handle.read())


def run_gui() -> int:
    app = QApplication([])
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(run_gui())
