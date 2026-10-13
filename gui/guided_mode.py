"""Guided mode widget for the Automated Penetration Testing Toolkit GUI."""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

try:
    from cybersentinel.config import get_ai_api_key, AI_MODELS
    from cybersentinel.reporting.report_gen import generate_report
except ImportError:
    from config import get_ai_api_key, AI_MODELS
    from reports.report_gen import generate_report
import importlib
from .results_panel import ResultsPanel
from .settings_dialog import SettingsManager, SettingsDialog


logger = logging.getLogger(__name__)


class ScanWorker(QThread):
    scan_started = pyqtSignal()
    scan_progress = pyqtSignal(int)
    scan_log = pyqtSignal(str)
    scan_finished = pyqtSignal(dict, dict, object, bool)
    scan_failed = pyqtSignal(str)

    def __init__(
        self,
        target: str,
        ports: List[int],
        use_ai: bool,
        pipeline: str = "FULL PENTEST PIPELINE",
        ai_provider: str = "claude",
        ai_api_key: Optional[str] = None,
        settings_manager: Optional[SettingsManager] = None,
    ) -> None:
        super().__init__()
        self.target = target
        self.ports = ports
        self.use_ai = use_ai
        self.pipeline = pipeline
        self.ai_provider = ai_provider
        self.ai_api_key = ai_api_key
        self.settings_manager = settings_manager
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _is_stopped(self) -> bool:
        return self._stop_requested

    def _log(self, message: str) -> None:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_log.emit(f"[{timestamp}] {message}")

    def _schedule_pipeline_tasks(self, scheduler: TaskScheduler) -> List:
        if self.pipeline == "RECON ONLY":
            return [scheduler.schedule_recon_task(self.target)]
        
        if self.pipeline == "PORT SCAN ONLY":
            tasks: List = []
            for port in self.ports:
                tasks.append(scheduler.schedule_port_scan_task(self.target, port, None))
            return tasks
        
        if self.pipeline == "WEB ASSESSMENT ONLY":
            return [scheduler.schedule_web_assessment_task(self.target, None)]
        
        if self.pipeline == "RECON + PORT SCAN":
            tasks: List = [scheduler.schedule_recon_task(self.target)]
            for port in self.ports:
                tasks.append(scheduler.schedule_port_scan_task(self.target, port, None))
            return tasks

        return scheduler.schedule_default_pipeline(self.target, ports=self.ports)

    def run(self) -> None:
        self.scan_started.emit()
        self.scan_progress.emit(8)

        try:
            self._log(f"INIT: Starting scan sequence for {self.target}...")
            time.sleep(0.25)

            try:
                from cybersentinel.core.scheduler import TaskScheduler
            except ImportError:
                from modules.scheduler import TaskScheduler
            scheduler = TaskScheduler()
            tasks = self._schedule_pipeline_tasks(scheduler)

            for index, task in enumerate(tasks, start=1):
                if self._is_stopped():
                    self._log("HALT: Stop requested, pausing scan and gathering partial results.")
                    break

                if task.task_type == "port_scan":
                    port = task.payload.get("port")
                    self._log(f"STEP: Executing port scan for port {port}...")
                elif task.task_type == "recon":
                    self._log("STEP: Executing recon stage...")
                elif task.task_type == "web_assessment":
                    self._log("STEP: Executing web assessment stage...")
                else:
                    self._log(f"STEP: Executing {task.task_type} stage...")

                scheduler.execute_task(task, stop_callback=self._is_stopped)
                percent = 8 + int(70 * index / len(tasks))
                self.scan_progress.emit(percent)

                if task.task_type == "port_scan":
                    port = task.payload.get("port")
                    self._log(f"DONE: Port scan for port {port} completed.")
                else:
                    self._log(f"DONE: {task.task_type.replace('_', ' ').capitalize()} stage completed.")

                time.sleep(0.22)

            if not self._is_stopped() and self.use_ai:
                self._log("AI: Generating contextual analysis...")
                ai_result = scheduler._run_ai_analysis_for_target(
                    self.target,
                    provider=self.ai_provider,
                    api_key=self.ai_api_key,
                    settings_manager=self.settings_manager,
                )
                if ai_result.get("error"):
                    self._log(f"AI: Analysis failed: {ai_result.get('error')}")
                else:
                    fallback_from = ai_result.get("fallback_from")
                    if fallback_from:
                        self._log(f"AI: Analysis completed successfully using fallback provider '{ai_result.get('provider')}' after '{fallback_from}' failed.")
                    else:
                        self._log("AI: Analysis completed successfully.")
                self.scan_progress.emit(95)
                time.sleep(0.18)

            results = scheduler.get_aggregated_results(self.target)
            risk_summary = scheduler.build_overall_risk_summary()
            report_path = None

            if self._is_stopped():
                self._log("FINISH: Scan stopped by user; partial results collected.")
            else:
                self._log("FINISH: Scan sequence completed successfully.")
                self.scan_progress.emit(100)

            self.scan_finished.emit(results, risk_summary, report_path, self._is_stopped())
        except Exception as exc:
            logger.exception("Scan failed for target %s", self.target)
            self.scan_failed.emit(str(exc))


class GuidedModeWidget(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.scan_worker: Optional[ScanWorker] = None
        self.settings_manager = SettingsManager()
        self._build_ui()
        self._on_ai_provider_changed()  # Load API key for default provider
        self._check_first_run()

    def _build_ui(self) -> None:
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 16)

        brand_label = QLabel("🛡 CyberSentinel Toolkit")
        brand_label.setObjectName("brandLabel")
        subtitle_label = QLabel("Automated Pentesting V1.0")
        subtitle_label.setObjectName("subtitleLabel")

        title_layout = QVBoxLayout()
        title_layout.addWidget(brand_label)
        title_layout.addWidget(subtitle_label)

        # Settings button
        settings_button = QPushButton("⚙️ Settings")
        settings_button.setObjectName("settingsButton")
        settings_button.setToolTip("Manage API keys and preferences")
        settings_button.clicked.connect(self._open_settings)
        settings_button.setMaximumWidth(120)

        self.mode_toggle = QPushButton("Guided Mode")
        self.mode_toggle.setCheckable(True)
        self.mode_toggle.setChecked(True)
        self.mode_toggle.setObjectName("modeToggleButton")
        self.mode_toggle.setToolTip("Toggle between Guided Mode and Expert Mode")
        self.mode_toggle.clicked.connect(self._toggle_mode)

        header_layout.addLayout(title_layout)
        header_layout.addStretch(1)
        header_layout.addWidget(settings_button)
        header_layout.addWidget(self.mode_toggle)

        self.target_input = QLineEdit("192.168.1.100")
        self.target_input.setObjectName("targetInput")
        self.ports_input = QLineEdit("80,443")
        self.ports_input.setObjectName("portsInput")
        self.ports_input.setToolTip("Enter ports (80,443 or 1-1000 or 'web_only', 'database', 'all_common')")

        self.pipeline_combo = QComboBox()
        self.pipeline_combo.addItems([
            "FULL PENTEST PIPELINE",
            "RECON ONLY",
            "PORT SCAN ONLY",
            "WEB ASSESSMENT ONLY",
            "RECON + PORT SCAN",
        ])
        self.pipeline_combo.setObjectName("pipelineCombo")

        self.ai_checkbox = QCheckBox("Enable AI analysis")
        self.ai_checkbox.setChecked(True)
        self.ai_checkbox.stateChanged.connect(self._on_ai_checkbox_changed)

        # AI Provider and API Key inputs
        self.ai_provider_combo = QComboBox()
        for provider_key, provider_info in AI_MODELS.items():
            self.ai_provider_combo.addItem(provider_info["name"], provider_key)
        self.ai_provider_combo.setObjectName("aiProviderCombo")
        self.ai_provider_combo.currentIndexChanged.connect(self._on_ai_provider_changed)

        self.ai_api_key_input = QLineEdit()
        self.ai_api_key_input.setObjectName("aiApiKeyInput")
        self.ai_api_key_input.setEchoMode(QLineEdit.Password)
        self.ai_api_key_input.setPlaceholderText("Enter API key or leave empty to use env variable")
        self.ai_api_key_input.setVisible(self.ai_checkbox.isChecked())

        self.scan_button = QPushButton("LAUNCH SCAN SEQUENCE")
        self.scan_button.setObjectName("launchButton")
        self.scan_button.clicked.connect(self._on_scan_clicked)

        self.stop_button = QPushButton("STOP SCAN")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._on_stop_clicked)

        self.console_output = QPlainTextEdit()
        self.console_output.setObjectName("consoleOutput")
        self.console_output.setReadOnly(True)
        self.status_label = QLabel("System: Idle")
        self.status_label.setObjectName("statusLabel")
        self.backend_status_label = QLabel()
        self.backend_status_label.setObjectName("backendStatusLabel")
        self.warning_label = QLabel("ETHICAL USE ONLY: Authorized Targets Only.")
        self.warning_label.setObjectName("warningLabel")

        try:
            scanner_module = importlib.import_module("modules.scanner")
            backend_status = scanner_module.validate_nmap_backends()
        except Exception as exc:
            backend_status = {"message": f"Scanner backend unavailable: {exc}"}
            self.scan_button.setEnabled(False)
            self.status_label.setText("System: Scan backend missing")

        self.console_output.setPlainText(
            "[2024-05-18 10:15:32] INIT: Ready to deploy scan...\n"
            "[2024-05-18 10:15:33] CONSOLE: Waiting for user action...\n"
            f"[{datetime.utcnow():%Y-%m-%d %H:%M:%S}] BACKEND: {backend_status['message']}"
        )
        self.backend_status_label.setText(f"Scan backend: {backend_status['message']}")

        self.results_panel = ResultsPanel()

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("footerProgress")
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p %")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        init_panel = QFrame()
        init_panel.setObjectName("panelCard")
        init_layout = QFormLayout(init_panel)
        init_layout.addRow(QLabel("Target"), self.target_input)
        init_layout.addRow(QLabel("Pipeline"), self.pipeline_combo)
        init_layout.addRow(QLabel("Ports"), self.ports_input)
        init_layout.addRow(QLabel(""), self.ai_checkbox)
        init_layout.addRow(QLabel("AI Provider"), self.ai_provider_combo)
        init_layout.addRow(QLabel("API Key"), self.ai_api_key_input)

        button_row = QHBoxLayout()
        button_row.addWidget(self.scan_button)
        button_row.addWidget(self.stop_button)
        init_layout.addRow(QLabel(""), button_row)

        console_panel = QFrame()
        console_panel.setObjectName("panelCard")
        console_layout = QVBoxLayout(console_panel)
        console_title = QLabel("2. Console Output")
        console_title.setObjectName("sectionTitle")
        console_layout.addWidget(console_title)
        console_layout.addWidget(self.console_output)

        analysis_panel = QFrame()
        analysis_panel.setObjectName("panelCard")
        analysis_layout = QVBoxLayout(analysis_panel)
        analysis_title = QLabel("3. Analysis & Findings")
        analysis_title.setObjectName("sectionTitle")
        analysis_layout.addWidget(analysis_title)
        analysis_layout.addWidget(self.results_panel)

        left_column = QVBoxLayout()
        left_column.addWidget(QLabel("1. Initialize Scan"))
        left_column.addWidget(init_panel)
        left_column.addStretch(1)

        middle_column = QVBoxLayout()
        middle_column.addWidget(console_panel)

        right_column = QVBoxLayout()
        right_column.addWidget(analysis_panel)

        content_layout = QHBoxLayout()
        content_layout.addLayout(left_column, 28)
        content_layout.addLayout(middle_column, 42)
        content_layout.addLayout(right_column, 30)
        content_layout.setSpacing(18)

        footer_layout = QHBoxLayout()
        footer_layout.addWidget(self.status_label)
        footer_layout.addWidget(self.backend_status_label)
        footer_layout.addWidget(self.progress_bar)
        footer_layout.addStretch(1)
        footer_layout.addWidget(self.warning_label)

        page_layout = QVBoxLayout(self)
        page_layout.addLayout(header_layout)
        page_layout.addLayout(content_layout)
        page_layout.addLayout(footer_layout)
        page_layout.setSpacing(16)
        page_layout.setContentsMargins(20, 20, 20, 20)

    def _toggle_mode(self) -> None:
        if self.mode_toggle.isChecked():
            self.mode_toggle.setText("Guided Mode")
            self.mode_toggle.setToolTip("Switch to Expert Mode")
            self.pipeline_combo.setToolTip("Select the scan pipeline for guided operation.")
        else:
            self.mode_toggle.setText("Expert Mode")
            self.mode_toggle.setToolTip("Switch to Guided Mode")
            self.pipeline_combo.setToolTip("Expert mode enabled; select the pipeline that best fits your target.")

    def _check_first_run(self) -> None:
        """Check if this is first run and no API keys are configured."""
        if not self.settings_manager.get_all_api_keys():
            # No API keys configured, show helpful info
            self.console_output.appendPlainText(
                "\n[INFO] No AI API keys configured.\n"
                "       Click the ⚙️ Settings button to add API keys for Claude or Gemini.\n"
                "       You can also use environment variables: ANTHROPIC_API_KEY, GEMINI_API_KEY\n"
            )

    def _parse_ports(self, port_text: str) -> List[int]:
        from config import COMMON_PORT_GROUPS
        ports: List[int] = []
        for token in port_text.split(","):
            token = token.strip().lower()
            if not token:
                continue
            # Check for port groups
            if token in COMMON_PORT_GROUPS:
                ports.extend(COMMON_PORT_GROUPS[token])
            elif "-" in token:
                start_text, end_text = token.split("-", 1)
                try:
                    start = int(start_text.strip())
                    end = int(end_text.strip())
                except ValueError as exc:
                    raise ValueError(f"Invalid port range '{token}'.") from exc
                if start <= end:
                    ports.extend(range(start, end + 1))
                else:
                    raise ValueError(f"Port range start must be <= end: {token}")
            else:
                try:
                    ports.append(int(token))
                except ValueError as exc:
                    raise ValueError(f"Invalid port value '{token}'.\nValid groups: web_only, database, all_common") from exc
        return sorted(set(ports))

    def _append_console_line(self, message: str) -> None:
        self.console_output.appendPlainText(message)
        self.console_output.verticalScrollBar().setValue(self.console_output.verticalScrollBar().maximum())

    def _on_scan_clicked(self) -> None:
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Validation Error", "Please enter a target hostname or IP address.")
            return

        port_text = self.ports_input.text().strip()
        try:
            ports = self._parse_ports(port_text) if port_text else [80, 443]
        except ValueError as exc:
            QMessageBox.warning(self, "Validation Error", str(exc))
            return

        use_ai = self.ai_checkbox.isChecked()
        pipeline = self.pipeline_combo.currentText()
        ai_provider = self.ai_provider_combo.currentData()
        ai_api_key = self.ai_api_key_input.text().strip() or None
        api_key_to_use = ai_api_key  # Will be updated below if needed

        if use_ai:
            # Check if API key is available (entered, settings, or environment)
            api_key_to_use = ai_api_key or get_ai_api_key(ai_provider, self.settings_manager)
            if not api_key_to_use:
                self._append_console_line(
                    f"[WARN] AI analysis enabled but no {AI_MODELS[ai_provider]['api_key_env']} is configured."
                )
                response = QMessageBox.question(
                    self,
                    "AI Key Not Found",
                    f"AI analysis is enabled but no {AI_MODELS[ai_provider]['api_key_env']} is configured.\n\n"
                    "Would you like to:\n"
                    "  • Click 'Yes' to open Settings and add an API key\n"
                    "  • Click 'No' to continue without AI analysis",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                if response == QMessageBox.Yes:
                    self._open_settings()
                    # After settings dialog, check if key is now available
                    api_key_to_use = ai_api_key or get_ai_api_key(ai_provider, self.settings_manager)
                    if not api_key_to_use:
                        use_ai = False
                        self._append_console_line("[INFO] Continuing scan without AI analysis.")
                else:
                    use_ai = False
                    self._append_console_line("[INFO] Continuing scan without AI analysis.")
            elif ai_api_key:
                # Save API key to settings for future use
                self.settings_manager.set_api_key(ai_provider, ai_api_key)
        else:
            self._append_console_line("[INFO] AI analysis is disabled for this scan.")

        self._set_scanning_state(True)
        self.results_panel.clear()
        self.console_output.clear()
        self.console_output.setPlainText(f"[{datetime.utcnow():%Y-%m-%d %H:%M:%S}] INIT: Launching scan for {target}...\nPipeline: {pipeline}")
        self.status_label.setText("System: Scanning...")
        self.progress_bar.setValue(8)

        self.scan_worker = ScanWorker(
            target=target,
            ports=ports,
            use_ai=use_ai,
            pipeline=pipeline,
            ai_provider=ai_provider,
            ai_api_key=api_key_to_use,
            settings_manager=self.settings_manager,
        )
        self.scan_worker.scan_started.connect(lambda: self._set_scanning_state(True))
        self.scan_worker.scan_progress.connect(self.progress_bar.setValue)
        self.scan_worker.scan_log.connect(self._append_console_line)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.scan_failed.connect(self._on_scan_failed)
        self.scan_worker.start()

    def _set_scanning_state(self, active: bool) -> None:
        self.scan_button.setEnabled(not active)
        self.stop_button.setEnabled(active)
        self.target_input.setEnabled(not active)
        self.ports_input.setEnabled(not active)
        self.pipeline_combo.setEnabled(not active)
        self.ai_checkbox.setEnabled(not active)
        self.ai_provider_combo.setEnabled(not active)
        self.ai_api_key_input.setEnabled(not active)
        self.mode_toggle.setEnabled(not active)

    def _on_ai_checkbox_changed(self) -> None:
        """Show/hide AI provider and API key inputs based on checkbox state."""
        is_checked = self.ai_checkbox.isChecked()
        self.ai_provider_combo.setVisible(is_checked)
        self.ai_api_key_input.setVisible(is_checked)

    def _on_ai_provider_changed(self) -> None:
        """Update API key input when AI provider changes."""
        provider = self.ai_provider_combo.currentData()
        # Load saved API key for this provider
        saved_key = self.settings_manager.get_api_key(provider)
        if saved_key:
            self.ai_api_key_input.setText(saved_key)
        else:
            self.ai_api_key_input.clear()
        # Update placeholder text
        api_key_env = AI_MODELS[provider]["api_key_env"]
        self.ai_api_key_input.setPlaceholderText(f"Enter {api_key_env} or use environment variable")

    def _open_settings(self) -> None:
        """Open the settings dialog."""
        dialog = SettingsDialog(self, self.settings_manager)
        if dialog.exec_() == SettingsDialog.Accepted:
            # Reload API key for current provider
            self._on_ai_provider_changed()

    def _on_stop_clicked(self) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.status_label.setText("System: Stopping scan...")
            self.stop_button.setEnabled(False)

    def _on_scan_finished(self, results: dict, risk_summary: dict, report_path: object, stopped: bool) -> None:
        if stopped:
            self.status_label.setText("System: Scan interrupted")
            self.progress_bar.setFormat("%p %")
        else:
            self.progress_bar.setValue(100)
            self.status_label.setText("System: Scan complete")
        self._set_scanning_state(False)

        self.results_panel.display_results(
            self.target_input.text().strip(),
            results,
            risk_summary,
            Path(str(report_path)) if report_path else None,
        )

        if report_path:
            QMessageBox.information(self, "Scan Complete", f"Scan finished and report generated:\n{report_path}")
        else:
            QMessageBox.information(self, "Scan Complete", "Scan finished. No HTML report was generated automatically. Use the button to generate one when you want it.")

    def _on_scan_failed(self, error_message: str) -> None:
        self.progress_bar.setValue(0)
        self.status_label.setText("System: Scan failed")
        self._set_scanning_state(False)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{error_message}")
