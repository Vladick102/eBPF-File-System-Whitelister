import sys
import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QListWidget,
    QTextEdit,
    QFileDialog,
    QMessageBox,
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont


class LogReaderThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, process):
        super().__init__()
        self.process = process
        self.running = True

    def run(self):
        for line in iter(self.process.stdout.readline, ""):
            if not self.running:
                break
            if "whitelister: BLOCK" in line:
                self.log_signal.emit(line.strip())

    def stop(self):
        self.running = False


class WhitelisterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proc_whitelister = None
        self.proc_trace = None
        self.log_thread = None
        self.running = False

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("eBPF FS Whitelister")
        self.resize(650, 550)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)

        comm_layout = QHBoxLayout()
        comm_label = QLabel("Target Process (comm):")
        comm_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        self.entry_comm = QLineEdit()
        self.entry_comm.setPlaceholderText("e.g., vsftpd, ftp")
        comm_layout.addWidget(comm_label)
        comm_layout.addWidget(self.entry_comm)
        main_layout.addLayout(comm_layout)

        path_label = QLabel("Allowed Paths (Max 8):")
        path_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        main_layout.addWidget(path_label)

        path_input_layout = QHBoxLayout()
        self.entry_path = QLineEdit()
        self.entry_path.setPlaceholderText("/path/to/allow")

        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self.browse_directory)

        btn_add = QPushButton("Add Path")
        btn_add.clicked.connect(self.add_path)

        path_input_layout.addWidget(self.entry_path)
        path_input_layout.addWidget(btn_browse)
        path_input_layout.addWidget(btn_add)
        main_layout.addLayout(path_input_layout)

        self.list_paths = QListWidget()
        main_layout.addWidget(self.list_paths)

        btn_remove = QPushButton("Remove Selected Path")
        btn_remove.clicked.connect(self.remove_path)
        main_layout.addWidget(btn_remove)

        self.btn_toggle = QPushButton("Start Enforcement")
        self.btn_toggle.setFont(QFont("Arimo", 12, QFont.Weight.Bold))
        self.btn_toggle.setMinimumHeight(40)
        self.btn_toggle.setStyleSheet(
            "background-color: #4CAF50; color: white; border-radius: 5px;"
        )
        self.btn_toggle.clicked.connect(self.toggle_enforcement)
        main_layout.addWidget(self.btn_toggle)

        log_label = QLabel("Kernel Denial Logs (trace_pipe):")
        log_label.setFont(QFont("Arimo", 10, QFont.Weight.Bold))
        main_layout.addWidget(log_label)

        self.text_logs = QTextEdit()
        self.text_logs.setReadOnly(True)
        self.text_logs.setStyleSheet(
            "background-color: #1e1e1e; color: #00ff00; font-family: monospace;"
        )
        main_layout.addWidget(self.text_logs)

    def browse_directory(self):
        """Opens the native OS directory picker."""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory to Whitelist"
        )
        if directory:
            self.entry_path.setText(directory)

    def add_path(self):
        path = self.entry_path.text().strip()
        if not path:
            return

        if self.list_paths.count() >= 8:
            QMessageBox.warning(
                self, "Limit Reached", "Maximum of 8 allowed prefixes reached."
            )
            return

        items = [self.list_paths.item(i).text() for i in range(self.list_paths.count())]
        if path not in items:
            self.list_paths.addItem(path)
            self.entry_path.clear()

            if self.running:
                self.log_message(f"[*] Live updating: Adding '{path}' to kernel...")
                self.apply_live_update()

    def remove_path(self):
        selected_items = self.list_paths.selectedItems()
        if not selected_items:
            return

        for item in selected_items:
            self.list_paths.takeItem(self.list_paths.row(item))

        if self.running:
            self.log_message("[*] Live updating: Removing path from kernel...")
            self.apply_live_update()

    def apply_live_update(self):
        if not self.running:
            return

        if self.proc_whitelister and self.proc_whitelister.poll() is None:
            subprocess.run(["sudo", "kill", "-SIGINT", str(self.proc_whitelister.pid)])
            self.proc_whitelister.wait()

        comm = self.entry_comm.text().strip()
        cmd = ["sudo", "./build/whitelister", "--comm", comm]
        for i in range(self.list_paths.count()):
            cmd.extend(["--allow", self.list_paths.item(i).text()])

        try:
            self.proc_whitelister = subprocess.Popen(cmd)
            self.log_message("[*] Rules successfully updated.")
        except Exception as e:
            self.log_message(f"[!] Error during live update: {e}")
            self.stop_enforcement()

    def log_message(self, msg):
        self.text_logs.append(msg)

    def toggle_enforcement(self):
        if self.running:
            self.stop_enforcement()
        else:
            self.start_enforcement()

    def start_enforcement(self):
        comm = self.entry_comm.text().strip()
        if not comm:
            QMessageBox.critical(self, "Error", "Process name (comm) is required.")
            return

        if self.list_paths.count() == 0:
            QMessageBox.critical(
                self, "Error", "At least one allowed path is required."
            )
            return

        cmd = ["sudo", "./build/whitelister", "--comm", comm]
        for i in range(self.list_paths.count()):
            cmd.extend(["--allow", self.list_paths.item(i).text()])

        try:
            self.proc_whitelister = subprocess.Popen(cmd)

            trace_cmd = ["sudo", "cat", "/sys/kernel/debug/tracing/trace_pipe"]
            self.proc_trace = subprocess.Popen(
                trace_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )

            self.log_thread = LogReaderThread(self.proc_trace)
            self.log_thread.log_signal.connect(self.log_message)
            self.log_thread.start()

            self.running = True
            self.btn_toggle.setText("Stop Enforcement")
            self.btn_toggle.setStyleSheet(
                "background-color: #f44336; color: white; border-radius: 5px;"
            )
            self.entry_comm.setEnabled(False)
            self.log_message(f"[*] Started enforcing '{comm}'...")

        except Exception as e:
            QMessageBox.critical(self, "Execution Error", str(e))
            self.stop_enforcement()

    def stop_enforcement(self):
        if self.proc_whitelister and self.proc_whitelister.poll() is None:
            subprocess.run(["sudo", "kill", "-SIGINT", str(self.proc_whitelister.pid)])

        if self.proc_trace and self.proc_trace.poll() is None:
            subprocess.run(["sudo", "kill", "-SIGTERM", str(self.proc_trace.pid)])

        if self.log_thread:
            self.log_thread.stop()
            self.log_thread.wait()

        self.running = False
        self.btn_toggle.setText("Start Enforcement")
        self.btn_toggle.setStyleSheet(
            "background-color: #4CAF50; color: white; border-radius: 5px;"
        )
        self.entry_comm.setEnabled(True)
        self.log_message("[*] Enforcement stopped.")

    def closeEvent(self, event):
        if self.running:
            self.stop_enforcement()
        event.accept()


if __name__ == "__main__":
    if not os.path.exists("./build/whitelister"):
        print(
            "Error: ./build/whitelister not found.\n"
            "Please ensure you are running this script from the project root directory, "
            "and that you have compiled the project using 'make' or './setup.sh build'."
        )
        sys.exit(1)

    app = QApplication(sys.argv)

    app.setStyle("Fusion")

    window = WhitelisterGUI()
    window.show()
    sys.exit(app.exec())
