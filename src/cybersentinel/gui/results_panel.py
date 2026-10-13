"""Results panel widget for the Automated Penetration Testing Toolkit GUI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)

from reports.report_gen import generate_report
from .report_dialog import ReportDialog


class ResultsPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.current_target: Optional[str] = None
        self.current_results: Dict[str, Any] = {}
        self.current_risk_summary: Dict[str, Any] = {}
        self.report_path: Optional[Path] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        self.risk_score_label = QLabel("78")
        self.risk_score_label.setObjectName("riskScoreLabel")
        self.risk_status_label = QLabel("CRITICAL")
        self.risk_status_label.setObjectName("riskStatusLabel")
        self.risk_detail_label = QLabel("Critical Ports: 2 / Vulnerabilities: 5")
        self.risk_detail_label.setObjectName("riskDetailLabel")

        risk_header = QHBoxLayout()
        risk_header.addWidget(self.risk_score_label)
        risk_text_layout = QVBoxLayout()
        risk_text_layout.addWidget(self.risk_status_label)
        risk_text_layout.addWidget(self.risk_detail_label)
        risk_header.addLayout(risk_text_layout)
        risk_header.addStretch(1)

        self.findings_list = QListWidget()
        self.findings_list.setObjectName("findingsList")

        self.ai_analysis_editor = QPlainTextEdit()
        self.ai_analysis_editor.setReadOnly(True)
        self.ai_analysis_editor.setObjectName("aiAnalysisEditor")
        self.ai_analysis_editor.setPlainText(
            "AI Analysis:\nNo AI analysis available yet. Run a scan and verify your configured provider and API key."
        )

        self.ai_provider_label = QLabel("AI Provider: None")
        self.ai_provider_label.setObjectName("aiProviderLabel")

        self.open_report_button = QPushButton("Open HTML Report")
        self.open_report_button.setEnabled(False)
        self.open_report_button.setObjectName("reportButton")
        self.open_report_button.clicked.connect(self._open_report_in_browser)

        self.generate_report_button = QPushButton("Generate Detailed HTML Report")
        self.generate_report_button.setObjectName("generateButton")
        self.generate_report_button.clicked.connect(self._generate_report)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.generate_report_button)
        button_layout.addWidget(self.open_report_button)

        layout.addLayout(risk_header)
        layout.addWidget(QLabel("Key Findings"))
        layout.addWidget(self.findings_list)
        layout.addWidget(QLabel("AI Analysis"))
        layout.addWidget(self.ai_provider_label)
        layout.addWidget(self.ai_analysis_editor)
        layout.addLayout(button_layout)

    def _open_report_in_browser(self) -> None:
        if not self.report_path:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.report_path)))

    def _generate_report(self) -> None:
        if not self.current_target or not self.current_results:
            return
        
        # Open report dialog for naming and location
        dialog = ReportDialog(self, target=self.current_target)
        if dialog.exec_() != ReportDialog.Accepted:
            return
        
        report_path = dialog.get_report_path()
        if not report_path:
            return
        
        # Generate report at specified location
        generate_report(
            self.current_target,
            self.current_results,
            risk_summary=self.current_risk_summary,
            output_path=report_path,
        )
        self.report_path = report_path
        self.open_report_button.setEnabled(True)
        self.ai_analysis_editor.appendPlainText(f"\n✓ Report generated: {report_path}")

    def display_results(
        self,
        target: str,
        results: Dict[str, Any],
        risk_summary: Dict[str, Any],
        report_path: Optional[Path] = None,
    ) -> None:
        self.current_target = target
        self.current_results = results
        self.current_risk_summary = risk_summary
        self.report_path = report_path
        self.open_report_button.setEnabled(bool(report_path))

        self.risk_score_label.setText(str(risk_summary.get("highest_score", 0)))
        self.risk_status_label.setText(risk_summary.get("severity", "LOW"))
        self.risk_detail_label.setText(
            f"Critical Ports: {risk_summary.get('total_findings', 0)} / Vulnerabilities: {risk_summary.get('highest_score', 0)}"
        )

        findings = []
        for data in results.get("results", {}).values():
            if isinstance(data, dict) and data.get("findings"):
                findings.extend(data["findings"])

        self.findings_list.clear()
        if not findings:
            self.findings_list.addItem("No findings detected.")
        else:
            for finding in findings:
                self.findings_list.addItem(str(finding))

        ai_info = results.get("results", {}).get("ai_analysis", {}) or {}
        ai_text = ai_info.get("analysis")
        ai_error = ai_info.get("error")
        ai_provider = ai_info.get("provider")
        fallback_from = ai_info.get("fallback_from")

        if ai_provider:
            provider_display = ai_provider
            if fallback_from:
                provider_display += f" (fallback from {fallback_from})"
            self.ai_provider_label.setText(f"AI Provider: {provider_display}")
        else:
            self.ai_provider_label.setText("AI Provider: None")

        if ai_text:
            self.ai_analysis_editor.setPlainText(ai_text)
        elif ai_error:
            self.ai_analysis_editor.setPlainText(
                f"AI analysis failed:\n{ai_error}"
            )
        else:
            self.ai_analysis_editor.setPlainText(
                "AI analysis has not been generated for this run.\nPlease verify the configured API key and provider settings."
            )

    def clear(self) -> None:
        self.current_target = None
        self.current_results = {}
        self.current_risk_summary = {}
        self.report_path = None
        self.risk_score_label.setText("0")
        self.risk_status_label.setText("LOW")
        self.risk_detail_label.setText("Critical Ports: 0 / Vulnerabilities: 0")
        self.findings_list.clear()
        self.ai_provider_label.setText("AI Provider: None")
        self.ai_analysis_editor.clear()
        self.open_report_button.setEnabled(False)
