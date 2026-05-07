#!/usr/bin/env python3
"""
Interfaz gráfica para el verificador de certificados SSL.
Utiliza el módulo ssl_checker como backend.
"""

import sys
import os
import threading
from datetime import datetime
from typing import List, Dict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QFileDialog, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QMessageBox, QGroupBox, QSpinBox, QStatusBar, QTabWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, pyqtSlot, QThread
from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor

# Importar nuestro módulo de verificación SSL
from ssl_checker import SSLCertChecker


class WorkerSignals(QObject):
    """Señales para comunicación entre el worker thread y la GUI."""
    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class SSLCheckWorker(QThread):
    """Worker thread para realizar las verificaciones SSL."""
    
    def __init__(self, urls: List[str], timeout: int = 10, max_workers: int = 10):
        super().__init__()
        self.urls = urls
        self.timeout = timeout
        self.max_workers = max_workers
        self.signals = WorkerSignals()
        self._is_running = True
        
    def run(self):
        """Ejecuta la verificación de certificados."""
        try:
            checker = SSLCertChecker(timeout=self.timeout)
            
            # Procesar URLs (modificado para emitir señales)
            urls_valid = [url.strip() for url in self.urls if url.strip()]
            total = len(urls_valid)
            
            for i, url in enumerate(urls_valid):
                if not self._is_running:
                    break
                    
                self.signals.progress.emit(f"Verificando {i+1}/{total}: {url.strip()}")
                
                # Realizar la verificación
                result = checker.process_url(url)
                
                # Emitir resultado
                self.signals.result.emit(result)
            
            self.signals.progress.emit("Verificación completada")
            self.signals.finished.emit()
            
        except Exception as e:
            self.signals.error.emit(str(e))
    
    def stop(self):
        """Detiene el worker."""
        self._is_running = False


class SSLCheckerGUI(QMainWindow):
    """Ventana principal de la aplicación."""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.results = {
            'valid': [],
            'invalid': []
        }
        self.init_ui()
        
    def init_ui(self):
        """Inicializa la interfaz de usuario."""
        self.setWindowTitle("Verificador de Certificados SSL")
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # Crear pestañas
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Pestaña de verificación
        self.check_tab = QWidget()
        self.tab_widget.addTab(self.check_tab, "Verificación")
        self.setup_check_tab()
        
        # Pestaña de resultados
        self.results_tab = QWidget()
        self.tab_widget.addTab(self.results_tab, "Resultados")
        self.setup_results_tab()

        # Pestaña de configuración
        config_tab = self.setup_config_tab()
        self.tab_widget.addTab(config_tab, "Configuración")
        
        # Barra de estado
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Listo para verificar")
        
    def setup_check_tab(self):
        """Configura la pestaña de verificación."""
        layout = QVBoxLayout(self.check_tab)
        
        # Grupo de configuración
        # config_group = QGroupBox("Configuración")
        # config_layout = QHBoxLayout(config_group)
        
        # Timeout
        # config_layout.addWidget(QLabel("Timeout (s):"))
        # self.timeout_spin = QSpinBox()
        # self.timeout_spin.setRange(1, 60)
        # self.timeout_spin.setValue(10)
        # config_layout.addWidget(self.timeout_spin)
        
        # Workers
        # config_layout.addWidget(QLabel("Workers:"))
        # self.workers_spin = QSpinBox()
        # self.workers_spin.setRange(1, 50)
        # self.workers_spin.setValue(10)
        # config_layout.addWidget(self.workers_spin)
        
        # config_layout.addStretch()
        # layout.addWidget(config_group)
        
        # Área de URLs
        urls_group = QGroupBox("URLs a verificar")
        urls_layout = QVBoxLayout(urls_group)
        
        # Botones de archivo
        file_layout = QHBoxLayout()
        
        self.load_btn = QPushButton("Cargar archivo")
        self.load_btn.clicked.connect(self.load_file)
        file_layout.addWidget(self.load_btn)
        
        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.clicked.connect(self.clear_urls)
        file_layout.addWidget(self.clear_btn)

        
        file_layout.addStretch()
        urls_layout.addLayout(file_layout)
        
        # Editor de URLs
        self.url_editor = QTextEdit()
        self.url_editor.setPlaceholderText(
            "Ingresa las URLs a verificar (una por línea)...\n"
            "Ejemplo:\n"
            "https://google.com\n"
            "github.com\n"
            "stackoverflow.com"
        )
        self.url_editor.setFont(QFont("Consolas", 10))
        urls_layout.addWidget(self.url_editor)
        
        layout.addWidget(urls_group)
        
        # Controles de verificación
        controls_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Iniciar Verificación")
        self.start_btn.clicked.connect(self.start_verification)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Detener")
        self.stop_btn.clicked.connect(self.stop_verification)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        controls_layout.addWidget(self.stop_btn)
        
        self.export_btn = QPushButton("Exportar Reporte")
        self.export_btn.clicked.connect(self.export_report)
        controls_layout.addWidget(self.export_btn)
        
        layout.addLayout(controls_layout)
        
        # Progreso
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Log de progreso
        log_group = QGroupBox("Progreso")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group)
        
    def setup_results_tab(self):
        """Configura la pestaña de resultados."""
        layout = QVBoxLayout(self.results_tab)
        
        # Splitter para dividir válidos e inválidos
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Tabla de certificados válidos
        valid_group = QGroupBox("Certificados Válidos")
        valid_layout = QVBoxLayout(valid_group)
        
        self.valid_table = QTableWidget()
        self.valid_table.setColumnCount(5)
        self.valid_table.setHorizontalHeaderLabels([
            "URL", "Hostname", "Emitido por", "Expira", "Días restantes"
        ])
        self.valid_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        valid_layout.addWidget(self.valid_table)
        splitter.addWidget(valid_group)
        
        # Tabla de certificados inválidos
        invalid_group = QGroupBox("Certificados Inválidos / Errores")
        invalid_layout = QVBoxLayout(invalid_group)
        
        self.invalid_table = QTableWidget()
        self.invalid_table.setColumnCount(3)
        self.invalid_table.setHorizontalHeaderLabels([
            "URL", "Hostname", "Error"
        ])
        self.invalid_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        invalid_layout.addWidget(self.invalid_table)
        splitter.addWidget(invalid_group)
        
        layout.addWidget(splitter)
        
        # Estadísticas
        stats_group = QGroupBox("Estadísticas")
        stats_layout = QHBoxLayout(stats_group)
        
        self.stats_label = QLabel("Total: 0 | Válidos: 0 | Inválidos: 0")
        self.stats_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        stats_layout.addWidget(self.stats_label)
        
        layout.addWidget(stats_group)
        
    def load_file(self):
        """Carga URLs desde un archivo."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de URLs",
            "",
            "Archivos de texto (*.txt);;Todos los archivos (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    urls = f.read()
                self.url_editor.setText(urls)
                self.log(f"Archivo cargado: {file_path}")
                self.status_bar.showMessage(f"Archivo cargado: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo cargar el archivo:\n{e}")

    def setup_config_tab(self):
        """Configura la pestaña de configuración"""
        config_tab = QWidget()
        config_main_layout = QVBoxLayout(config_tab)
        
        # Grupo de Configuración General
        config_group = QGroupBox("Configuración General")
        config_layout = QHBoxLayout(config_group)
        
        # Timeout
        config_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setToolTip("Tiempo máximo de espera en segundos")
        config_layout.addWidget(self.timeout_spin)
        
        # Separador
        config_layout.addSpacing(20)
        
        # Workers
        config_layout.addWidget(QLabel("Workers:"))
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 50)
        self.workers_spin.setValue(10)
        self.workers_spin.setToolTip("Número de workers simultáneos")
        config_layout.addWidget(self.workers_spin)
        
        config_layout.addStretch()
        config_main_layout.addWidget(config_group)
        config_main_layout.addStretch()
        
        return config_tab
    
    def clear_urls(self):
        """Limpia el editor de URLs."""
        self.url_editor.clear()
        
    def get_urls(self) -> List[str]:
        """Obtiene las URLs del editor."""
        return self.url_editor.toPlainText().splitlines()
    
    def start_verification(self):
        """Inicia la verificación de certificados."""
        urls = self.get_urls()
        
        if not urls or all(not url.strip() for url in urls):
            QMessageBox.warning(self, "Advertencia", "Ingresa al menos una URL para verificar.")
            return
        
        # Limpiar resultados anteriores
        self.results = {'valid': [], 'invalid': []}
        self.valid_table.setRowCount(0)
        self.invalid_table.setRowCount(0)
        self.log_text.clear()
        
        # Deshabilitar controles durante la verificación
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.load_btn.setEnabled(False)
        self.url_editor.setReadOnly(True)
        
        # Mostrar barra de progreso
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(0)  # Modo indeterminado
        
        # Crear y ejecutar worker
        self.worker = SSLCheckWorker(
            urls=urls,
            timeout=self.timeout_spin.value(),
            max_workers=self.workers_spin.value()
        )
        
        # Conectar señales
        self.worker.signals.progress.connect(self.update_progress)
        self.worker.signals.result.connect(self.process_result)
        self.worker.signals.finished.connect(self.verification_finished)
        self.worker.signals.error.connect(self.verification_error)
        
        # Iniciar worker
        self.worker.start()
        self.status_bar.showMessage("Verificando certificados...")
    
    def stop_verification(self):
        """Detiene la verificación."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            self.log("Verificación detenida por el usuario")
            self.status_bar.showMessage("Verificación detenida")
            self.reset_controls()
    
    @pyqtSlot(str)
    def update_progress(self, message: str):
        """Actualiza el mensaje de progreso."""
        self.log(message)
        
    @pyqtSlot(dict)
    def process_result(self, result: Dict):
        """Procesa un resultado individual."""
        if result['status'] == 'valid':
            self.results['valid'].append(result)
            self.add_valid_row(result)
        else:
            self.results['invalid'].append(result)
            self.add_invalid_row(result)
        
        # Actualizar estadísticas
        total = len(self.results['valid']) + len(self.results['invalid'])
        self.stats_label.setText(
            f"Total: {total} | "
            f"Válidos: {len(self.results['valid'])} | "
            f"Inválidos: {len(self.results['invalid'])}"
        )
        
    @pyqtSlot()
    def verification_finished(self):
        """Maneja la finalización de la verificación."""
        self.log("✅ Verificación completada")
        self.status_bar.showMessage("Verificación completada")
        self.reset_controls()
        
        # Cambiar a la pestaña de resultados
        self.tab_widget.setCurrentIndex(1)
        
        # Mostrar resumen
        QMessageBox.information(
            self,
            "Verificación Completada",
            f"Resultados:\n"
            f"✅ Certificados válidos: {len(self.results['valid'])}\n"
            f"❌ Sin certificado/Errores: {len(self.results['invalid'])}"
        )
    
    @pyqtSlot(str)
    def verification_error(self, error_msg: str):
        """Maneja errores de verificación."""
        self.log(f"❌ Error: {error_msg}")
        QMessageBox.critical(self, "Error", f"Error durante la verificación:\n{error_msg}")
        self.reset_controls()
    
    def reset_controls(self):
        """Restablece los controles a su estado inicial."""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.load_btn.setEnabled(True)
        self.url_editor.setReadOnly(False)
        self.progress_bar.setVisible(False)
    
    def add_valid_row(self, result: Dict):
        """Añade una fila a la tabla de certificados válidos."""
        row = self.valid_table.rowCount()
        self.valid_table.insertRow(row)
        
        cert_info = result.get('cert_info', {})
        issuer = cert_info.get('issuer', {}).get('organizationName', 'Desconocido')
        
        items = [
            QTableWidgetItem(result['url']),
            QTableWidgetItem(result['hostname']),
            QTableWidgetItem(issuer),
            QTableWidgetItem(cert_info.get('notAfter', 'N/A')),
            QTableWidgetItem(str(cert_info.get('days_until_expiry', 'N/A')))
        ]
        
        # Colorear según días restantes
        days = cert_info.get('days_until_expiry', 0)
        if isinstance(days, (int, float)):
            if days <= 30:
                color = QColor(255, 100, 100)  # Rojo claro
            elif days <= 90:
                color = QColor(184, 134, 11)  # Amarillo claro
            else:
                color = QColor(50, 255, 50)  # Verde claro
            
            for item in items:
                item.setBackground(color)
        
        for col, item in enumerate(items):
            self.valid_table.setItem(row, col, item)
    
    def add_invalid_row(self, result: Dict):
        """Añade una fila a la tabla de certificados inválidos."""
        row = self.invalid_table.rowCount()
        self.invalid_table.insertRow(row)
        
        items = [
            QTableWidgetItem(result['url']),
            QTableWidgetItem(result['hostname']),
            QTableWidgetItem(result.get('error', 'Error desconocido'))
        ]
        
        # Color rojo claro para errores
        for item in items:
            item.setBackground(QColor(250, 0, 0))
        
        for col, item in enumerate(items):
            self.invalid_table.setItem(row, col, item)
    
    def export_report(self):
        """Exporta el reporte a un archivo."""
        if not self.results['valid'] and not self.results['invalid']:
            QMessageBox.warning(self, "Advertencia", "No hay resultados para exportar.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar reporte",
            f"reporte_ssl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Archivos de texto (*.txt);;Todos los archivos (*)"
        )
        
        if file_path:
            try:
                # Usar el checker solo para generar el reporte
                from ssl_checker import SSLCertChecker
                checker = SSLCertChecker()
                checker.results = self.results
                checker.generate_report(output_file=file_path)
                
                QMessageBox.information(
                    self,
                    "Éxito",
                    f"Reporte exportado correctamente a:\n{file_path}"
                )
                self.log(f"📄 Reporte exportado: {file_path}")
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"No se pudo exportar el reporte:\n{e}"
                )
    
    def log(self, message: str):
        """Añade un mensaje al log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        # Scroll al final
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_text.setTextCursor(cursor)


def main():
    """Función principal."""
    app = QApplication(sys.argv)
    
    # Estilo moderno
    app.setStyle('Fusion')
    
    # Tema oscuro opcional
    """
    dark_stylesheet = '''
        QMainWindow { background-color: #2b2b2b; }
        QTextEdit, QTableWidget { 
            background-color: #3c3f41; 
            color: #a9b7c6; 
        }
        QLabel { color: #a9b7c6; }
        QGroupBox { 
            color: #a9b7c6; 
            border: 1px solid #555;
            border-radius: 5px;
            margin-top: 10px;
        }
    '''
    app.setStyleSheet(dark_stylesheet)
    """
    
    window = SSLCheckerGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
