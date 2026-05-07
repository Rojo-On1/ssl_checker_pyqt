#!/usr/bin/env python3
"""
Script para verificar certificados SSL de URLs desde un archivo de texto.
Reporta qué sitios tienen certificado válido y cuáles no.

Uso: python check_certs.py archivo_urls.txt [-o reporte.txt]
"""

import ssl
import socket
import argparse
import sys
from urllib.parse import urlparse
from datetime import datetime, timezone
import concurrent.futures
from typing import Tuple, Optional
import re
from dateutil import parser
import pandas as pd

class SSLCertChecker:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }
    
    def clean_url(self, url: str) -> str:
        """Limpia y normaliza la URL."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def get_hostname(self, url: str) -> str:
        """Extrae el hostname de la URL."""
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        # Eliminar puerto si existe
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        return hostname

    def get_ip_address(self, hostname: str) -> str:
        """Obtiene la dirección IP local del hostname."""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return "No resuelve"
        except Exception:
            return "Error"

    def check_certificate(self, hostname: str, port: int = 443) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Verifica el certificado SSL de un hostname.
        Retorna: (tiene_cert_valido, mensaje_error, info_certificado)
        """
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar fecha de expiración
                    not_after = parser.parse(re.sub(r'\s+', ' ',cert['notAfter']))
                    
                    days_until_expiry = (not_after - datetime.now(timezone.utc)).days
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notAfter': cert['notAfter'],
                        'days_until_expiry': days_until_expiry
                    }
                    
                    if days_until_expiry < 0:
                        return False, "Certificado expirado", cert_info
                    
                    return True, None, cert_info
                    
        except ssl.SSLError as e:
            return False, f"Error SSL: {str(e)}", None
        except socket.timeout:
            return False, "Timeout de conexión", None
        except socket.gaierror:
            return False, "No se pudo resolver el nombre de dominio", None
        except ConnectionRefusedError:
            return False, "Conexión rechazada", None
        except OSError as e:
            if e.errno == 113:
                return False, f"No hay ruta hasta el host '{hostname}'. Verifique conectividad de red.", None
            elif e.errno == 101:  
                return False, f"Red no accesible para '{hostname}'.", None
            elif e.errno == 111:
                return False, "Conexión rechazada", None
            else:
                return False, f"Error de red ({e.errno}): {str(e)}", None
        except Exception as e:
            return False, f"Error inesperado: {str(e)}", None
    
    def process_url(self, url: str) -> dict:
        """Procesa una URL y retorna el resultado."""
        original_url = url.strip()
        url = self.clean_url(url)
        hostname = self.get_hostname(url)
        ip_address = self.get_ip_address(hostname)
        
        print(f"Verificando: {hostname}...", end=" ")
        
        # Intentar puerto 443 (HTTPS)
        has_cert, error, cert_info = self.check_certificate(hostname)
        
        if has_cert:
            expiry_days = cert_info['days_until_expiry']
            print(f"✓ Válido (expira en {expiry_days} días)")
            return {
                'url': original_url,
                'hostname': hostname,
                'status': 'valid',
                'cert_info': cert_info
            }
        else:
            # Si hay error, intentar conexión HTTP para ver si el sitio existe
            try:
                socket.create_connection((hostname, 80), timeout=5)
                print(f"✗ Sin certificado HTTPS válido: {error}")
            except:
                print(f"✗ Error de conexión: {error}")
            
            return {
                'url': original_url,
                'hostname': hostname,
                'status': 'invalid',
                'error': error
            }
    
    def process_urls(self, urls: list, max_workers: int = 10):
        """Procesa múltiples URLs en paralelo."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.process_url, url): url for url in urls if url.strip()}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result['status'] == 'valid':
                    self.results['valid'].append(result)
                else:
                    self.results['invalid'].append(result)
    
    def generate_report(self, output_file: Optional[str] = None):
        """Genera un reporte en Excel con las columnas requeridas."""
        rows = []
        
        # Procesar sitios con certificado válido
        for site in self.results['valid']:
            cert_info = site['cert_info']
            rows.append({
                'Dirección correcto (URL)': site['url'],
                'Dirección de IP Local': site.get('ip', 'No resuelve'),
                'TIENE CERTIFICADO': 'X',
                'FECHA DE VENCIMIENTO': cert_info['notAfter'],
                'ENTIDAD CERTIFICADORA': cert_info['issuer'].get('organizationName', 'Desconocido')
            })
        
        # Procesar sitios sin certificado o con error
        for site in self.results['invalid']:
            rows.append({
                'Dirección correcto (URL)': site['url'],
                'Dirección de IP Local': site.get('ip', 'No resuelve'),
                'TIENE CERTIFICADO': '',
                'FECHA DE VENCIMIENTO': '',
                'ENTIDAD CERTIFICADORA': ''
            })
        
        # Crear DataFrame y guardar a Excel
        df = pd.DataFrame(rows)
        df.to_excel(output_file, index=False, sheet_name='Certificados SSL')
        print(f"\nReporte Excel guardado en: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Verifica certificados SSL de URLs listadas en un archivo de texto.'
    )
    parser.add_argument(
        'archivo',
        help='Archivo de texto con las URLs (una por línea)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Archivo de salida para el reporte (opcional)',
        default=None
    )
    parser.add_argument(
        '-t', '--timeout',
        help='Timeout en segundos para cada conexión (default: 10)',
        type=int,
        default=10
    )
    parser.add_argument(
        '-w', '--workers',
        help='Número de workers para procesamiento paralelo (default: 10)',
        type=int,
        default=10
    )
    
    args = parser.parse_args()
    
    # Leer URLs del archivo
    try:
        with open(args.archivo, 'r', encoding='utf-8') as f:
            urls = f.readlines()
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{args.archivo}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error al leer el archivo: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not urls or all(not url.strip() for url in urls):
        print("Error: El archivo está vacío", file=sys.stderr)
        sys.exit(1)
    
    # Procesar URLs
    print(f"Procesando {len([u for u in urls if u.strip()])} URLs...\n")
    checker = SSLCertChecker(timeout=args.timeout)
    checker.process_urls(urls, max_workers=args.workers)
    
    # Generar reporte
    checker.generate_report(output_file=args.output)

if __name__ == "__main__":
    main()
