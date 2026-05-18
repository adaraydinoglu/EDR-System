"""
main.py — EDR Sistemi Giriş Noktası
PyQt6 GUI başlatır; backend GUI üzerinden yönetilir.
"""
import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from gui.main_window import MainWindow


def main():
    # Hi-DPI desteği
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("EDR Koruma Sistemi")
    app.setQuitOnLastWindowClosed(False)  # Tray'de yaşamaya devam etsin

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()