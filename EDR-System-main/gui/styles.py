DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #12121f;
}
QWidget {
    background-color: #12121f;
    color: #e0e0e0;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #2a2a3e;
    background-color: #1a1a2e;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #1a1a2e;
    color: #8888aa;
    padding: 10px 20px;
    border: 1px solid #2a2a3e;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #e94560;
    color: white;
    font-weight: bold;
}
QTabBar::tab:hover:!selected {
    background-color: #0f3460;
    color: #ccccff;
}
QPushButton {
    background-color: #0f3460;
    color: white;
    border: none;
    padding: 8px 24px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #1a4a80;
}
QPushButton:pressed {
    background-color: #0a2040;
}
QPushButton#startButton {
    background-color: #1e6b3c;
    min-width: 120px;
}
QPushButton#startButton:hover {
    background-color: #28834a;
}
QPushButton#stopButton {
    background-color: #8b0000;
    min-width: 120px;
}
QPushButton#stopButton:hover {
    background-color: #a00000;
}
QTableWidget {
    background-color: #1a1a2e;
    gridline-color: #2a2a3e;
    border: none;
    selection-background-color: #0f3460;
}
QTableWidget::item {
    padding: 5px 8px;
    border-bottom: 1px solid #2a2a3e;
}
QHeaderView::section {
    background-color: #0f3460;
    color: #a0c4ff;
    padding: 8px;
    border: none;
    border-right: 1px solid #2a2a3e;
    font-weight: bold;
    font-size: 12px;
}
QStatusBar {
    background-color: #0a0a1a;
    color: #6688aa;
    border-top: 1px solid #2a2a3e;
}
QLabel#headerLabel {
    font-size: 18px;
    font-weight: bold;
    color: #e94560;
    padding: 4px 0px;
}
QLabel#statusDot {
    font-size: 22px;
}
QListWidget {
    background-color: #1a1a2e;
    border: none;
    color: #c0c0d0;
}
QListWidget::item {
    padding: 4px 8px;
    border-bottom: 1px solid #2a2a3e;
    font-family: Consolas, monospace;
    font-size: 12px;
}
QListWidget::item:hover {
    background-color: #0f3460;
}
QComboBox {
    background-color: #1a1a2e;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    padding: 5px 10px;
    border-radius: 4px;
    min-width: 180px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #1a1a2e;
    border: 1px solid #2a2a3e;
    color: #c0c0d0;
    selection-background-color: #0f3460;
}
QScrollBar:vertical {
    background-color: #12121f;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background-color: #2a2a5e;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #3a3a7e;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QFrame#statCard {
    border-radius: 10px;
    border: 1px solid #2a2a4e;
}
QTextEdit {
    background-color: #1a1a2e;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    font-family: Consolas, monospace;
    font-size: 12px;
}
"""
