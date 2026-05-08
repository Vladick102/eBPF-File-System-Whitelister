import re
import signal
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


SCRIPT_DIR = Path(__file__).resolve().parent
BIN_PATH = SCRIPT_DIR / "build" / "whitelister"
CONFIG_PATH = SCRIPT_DIR / "whitelister_config.h"
SUDO_PASSWORD_HINT = (
    "[*] If sudo asks for a password, enter it in the terminal where "
    "you launched gui.py."
)


def read_config_limits():
    defaults = {
        "MAX_COMMS": 16,
        "MAX_PREFIXES": 128,
        "LPM_PATH_MAX": 240,
        "TASK_COMM_LEN": 16,
    }
    try:
        text = CONFIG_PATH.read_text()
    except OSError:
        return defaults

    for name in defaults:
        match = re.search(rf"^\s*#define\s+{name}\s+(\d+)\b", text, re.MULTILINE)
        if match:
            defaults[name] = int(match.group(1))
    return defaults


LIMITS = read_config_limits()
MAX_COMMS = LIMITS["MAX_COMMS"]
MAX_PREFIXES = LIMITS["MAX_PREFIXES"]
LPM_PATH_MAX = LIMITS["LPM_PATH_MAX"]
TASK_COMM_MAX = LIMITS["TASK_COMM_LEN"] - 1


class StreamReaderThread(QThread):
    line_signal = pyqtSignal(str)

    def __init__(self, process, filter_text=None):
        super().__init__()
        self.process = process
        self.filter_text = filter_text
        self.running = True

    def run(self):
        if not self.process.stdout:
            return

        for line in iter(self.process.stdout.readline, ""):
            if not self.running:
                break
            line = line.strip()
            if not line:
                continue
            if self.filter_text and self.filter_text not in line:
                continue
            self.line_signal.emit(line)

    def stop(self):
        self.running = False


class WhitelisterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proc_whitelister = None
        self.proc_trace = None
        self.whitelister_thread = None
        self.trace_thread = None
        self.running = False

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("eBPF FS Whitelister")
        self.resize(820, 620)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(12)

        target_label = QLabel("Policy Entry")
        target_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        main_layout.addWidget(target_label)

        comm_layout = QHBoxLayout()
        comm_label = QLabel("Process comm:")
        self.entry_comm = QLineEdit()
        self.entry_comm.setPlaceholderText("e.g., vsftpd, sshd, ftp")
        comm_layout.addWidget(comm_label)
        comm_layout.addWidget(self.entry_comm)
        main_layout.addLayout(comm_layout)

        path_layout = QHBoxLayout()
        path_label = QLabel("Allowed path:")
        self.entry_path = QLineEdit()
        self.entry_path.setPlaceholderText("/path/to/allow")

        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self.browse_directory)

        btn_add = QPushButton("Add Prefix")
        btn_add.clicked.connect(self.add_policy)

        path_layout.addWidget(path_label)
        path_layout.addWidget(self.entry_path)
        path_layout.addWidget(btn_browse)
        path_layout.addWidget(btn_add)
        main_layout.addLayout(path_layout)

        policies_label = QLabel(
            f"Configured Policies ({MAX_COMMS} comms, {MAX_PREFIXES} prefixes max)"
        )
        policies_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        main_layout.addWidget(policies_label)

        self.policy_tree = QTreeWidget()
        self.policy_tree.setHeaderLabels(["Process comm", "Allowed prefix"])
        self.policy_tree.header().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.policy_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.policy_tree.setAlternatingRowColors(True)
        main_layout.addWidget(self.policy_tree)

        btn_remove = QPushButton("Remove Selected Prefix")
        btn_remove.clicked.connect(self.remove_selected_policy)
        main_layout.addWidget(btn_remove)

        self.btn_toggle = QPushButton("Start Enforcement")
        self.btn_toggle.setFont(QFont("Arimo", 12, QFont.Weight.Bold))
        self.btn_toggle.setMinimumHeight(40)
        self.btn_toggle.setStyleSheet(
            "background-color: #2e7d32; color: white; border-radius: 5px;"
        )
        self.btn_toggle.clicked.connect(self.toggle_enforcement)
        main_layout.addWidget(self.btn_toggle)

        log_label = QLabel("Output and Kernel Denial Logs")
        log_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        main_layout.addWidget(log_label)

        self.text_logs = QTextEdit()
        self.text_logs.setReadOnly(True)
        self.text_logs.setStyleSheet(
            "background-color: #1e1e1e; color: #00e676; font-family: monospace;"
        )
        main_layout.addWidget(self.text_logs)

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory to Whitelist"
        )
        if directory:
            self.entry_path.setText(directory)

    def add_policy(self):
        comm = self.entry_comm.text().strip()
        path = self.entry_path.text().strip()

        if not comm:
            QMessageBox.warning(self, "Missing Process", "Process comm is required.")
            return
        if not path:
            QMessageBox.warning(self, "Missing Path", "Allowed path is required.")
            return
        if len(comm.encode()) > TASK_COMM_MAX:
            QMessageBox.warning(
                self,
                "Process Name Too Long",
                f"Linux comm values are truncated to {TASK_COMM_MAX} bytes.",
            )
            return

        path = self.canonicalise_path(path)
        if len(path.encode()) > LPM_PATH_MAX:
            QMessageBox.warning(
                self,
                "Path Too Long",
                f"Allowed prefixes can be at most {LPM_PATH_MAX} bytes.",
            )
            return

        policies = self.policies()
        if len(policies) >= MAX_PREFIXES:
            QMessageBox.warning(
                self,
                "Limit Reached",
                f"Maximum of {MAX_PREFIXES} allowed prefixes reached.",
            )
            return

        comms = {policy_comm for policy_comm, _ in policies}
        if comm not in comms and len(comms) >= MAX_COMMS:
            QMessageBox.warning(
                self,
                "Limit Reached",
                f"Maximum of {MAX_COMMS} distinct process comms reached.",
            )
            return

        if (comm, path) in policies:
            return

        self.policy_tree.addTopLevelItem(QTreeWidgetItem([comm, path]))
        self.entry_path.clear()

        if self.running:
            self.log_message(f"[*] Live updating policy: {comm} -> {path}")
            self.apply_live_update()

    def remove_selected_policy(self):
        selected_items = self.policy_tree.selectedItems()
        if not selected_items:
            return

        for item in selected_items:
            index = self.policy_tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.policy_tree.takeTopLevelItem(index)

        if self.running:
            self.log_message("[*] Live updating policy after removal")
            self.apply_live_update()

    def policies(self):
        return [
            (
                self.policy_tree.topLevelItem(i).text(0),
                self.policy_tree.topLevelItem(i).text(1),
            )
            for i in range(self.policy_tree.topLevelItemCount())
        ]

    def build_command(self):
        cmd = ["sudo", str(BIN_PATH)]
        current_comm = None

        for comm, path in sorted(self.policies()):
            if comm != current_comm:
                cmd.extend(["--comm", comm])
                current_comm = comm
            cmd.extend(["--allow", path])

        return cmd

    def apply_live_update(self):
        if not self.running:
            return

        if not self.policies():
            self.log_message("[*] No policies remain; stopping enforcement.")
            self.stop_enforcement()
            return

        self.stop_whitelister_process()
        self.start_whitelister_process()
        self.log_message("[*] Rules successfully updated.")

    def log_message(self, msg):
        self.text_logs.append(msg)

    def toggle_enforcement(self):
        if self.running:
            self.stop_enforcement()
        else:
            self.start_enforcement()

    def start_enforcement(self):
        if not self.policies():
            QMessageBox.critical(
                self,
                "Error",
                "Add at least one process comm and allowed path prefix.",
            )
            return

        try:
            self.start_whitelister_process()
            self.start_trace_process()
        except Exception as e:
            QMessageBox.critical(self, "Execution Error", str(e))
            self.stop_enforcement()
            return

        self.running = True
        self.btn_toggle.setText("Stop Enforcement")
        self.btn_toggle.setStyleSheet(
            "background-color: #c62828; color: white; border-radius: 5px;"
        )
        self.log_message("[*] Enforcement started.")
        self.log_message(SUDO_PASSWORD_HINT)

    def start_whitelister_process(self):
        cmd = self.build_command()
        self.proc_whitelister = subprocess.Popen(
            cmd,
            cwd=SCRIPT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        self.whitelister_thread = StreamReaderThread(self.proc_whitelister)
        self.whitelister_thread.line_signal.connect(self.log_message)
        self.whitelister_thread.start()

    def start_trace_process(self):
        trace_cmd = ["sudo", "cat", "/sys/kernel/debug/tracing/trace_pipe"]
        self.proc_trace = subprocess.Popen(
            trace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        self.trace_thread = StreamReaderThread(
            self.proc_trace, filter_text="whitelister: BLOCK"
        )
        self.trace_thread.line_signal.connect(self.log_message)
        self.trace_thread.start()

    def stop_enforcement(self):
        self.stop_whitelister_process()
        self.stop_trace_process()

        self.running = False
        self.btn_toggle.setText("Start Enforcement")
        self.btn_toggle.setStyleSheet(
            "background-color: #2e7d32; color: white; border-radius: 5px;"
        )
        self.log_message("[*] Enforcement stopped.")

    def stop_whitelister_process(self):
        self.stop_process(self.proc_whitelister, signal.SIGINT)
        self.proc_whitelister = None
        self.stop_thread(self.whitelister_thread)
        self.whitelister_thread = None

    def stop_trace_process(self):
        self.stop_process(self.proc_trace, signal.SIGTERM)
        self.proc_trace = None
        self.stop_thread(self.trace_thread)
        self.trace_thread = None

    def stop_process(self, process, sig):
        if process and process.poll() is None:
            subprocess.run(["sudo", "kill", f"-{sig.name}", str(process.pid)])
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                subprocess.run(["sudo", "kill", "-SIGKILL", str(process.pid)])
                process.wait(timeout=3)

    def stop_thread(self, thread):
        if thread:
            thread.stop()
            thread.wait(1000)

    def closeEvent(self, event):
        if self.running:
            self.stop_enforcement()
        event.accept()

    @staticmethod
    def canonicalise_path(path):
        path = path.rstrip("/")
        return path if path else "/"


if __name__ == "__main__":
    if not BIN_PATH.exists():
        print(
            f"Error: {BIN_PATH} not found.\n"
            "Build the project first with 'make' or './setup.sh build' from "
            f"{SCRIPT_DIR}."
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = WhitelisterGUI()
    window.show()
    sys.exit(app.exec())
