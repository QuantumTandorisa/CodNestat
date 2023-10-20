# -*- coding: utf-8 -*-
'''
   _____                      _ __             _____            __          
  / ___/___  _______  _______(_) /___  __     / ___/__  _______/ /____   ____ ___        
  \__ \/ _ \/ ___/ / / / ___/ / __/ / / /_____\__ \/ / / / ___/ __/ _ \ / __ `__ \            
 ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ //____/__/ / /_/ (__  ) /_/  __// / / / / /                
/____/\___/\___/\__,_/_/  /_/\__/\__, /     /____/\__, /____/\__/\___//_/ /_/ /_/          
                                /____/           /____/                
'''
#######################################################
#    Security-System.py
#
# Security System is a powerful security tool designed
# to protect and monitor your system. It offers a wide 
# range of functions to detect and respond to potential
# security threats, as well as to track network activity
# and system status. To date, I have successfully 
# resolved several bugs, and will continue to work on 
# constantly improving the software. I am pleased to 
# announce that the next upgrade is scheduled for 
# January 2024.
#
#
# 10/18/23 - Changed to Python3 (finally)
#
# Author: Facundo Fernandez 
#
#
#######################################################

from multiprocessing import connection
import os
import re
import subprocess
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
#import psutil
import socket
#from tkinter.ttk import _Padding
import requests
import geoip2.database
import hashlib
import time
import ssl
import platform
#import pybox
import magic
import PyPDF2
from PIL import Image
#import win32api
import pandas as pd
import joblib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json

# Cargar configuración desde config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Acceder a opciones de configuración
api_key = config.get('api_key', 'tu_clave_de_api')
debug_mode = config.get('debug_mode', False)
archivo_log = config.get('archivo_log', 'log.txt')

def get_system_type():
    return platform.system()

def verify_file_integrity(file_path, expected_hash):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            file_hash = hashlib.sha256(data).hexdigest()
            if file_hash == expected_hash:
                return True
            else:
                return False
    except FileNotFoundError:
        return False

def monitor_resource_usage(pid):
    try:
        process = psutil.Process(pid)
        cpu_percent = process.cpu_percent()
        memory_usage = process.memory_info().rss
        disk_usage = process.io_counters().read_bytes + process.io_counters().write_bytes
        return cpu_percent, memory_usage, disk_usage
    except psutil.NoSuchProcess:
        return None, None, None

def analyze_network_traffic():
    connections = psutil.net_connections()
    total_bytes_sent = 0
    total_bytes_received = 0
    established_connections = 0
    connections_by_port = {}
    connection_durations = []
    suspicious_connections = []

    for connection in connections:
        if connection.status == "ESTABLISHED":
            established_connections += 1

        total_bytes_sent += connection.bytes_sent
        total_bytes_received += connection.bytes_recv

        # Count connections per port / Contar conexiones por puerto
        local_port = connection.laddr.port
        if local_port in connections_by_port:
            connections_by_port[local_port] += 1
        else:
            connections_by_port[local_port] = 1

        # Calculate connection duration / Calcular la duración de la conexión
        if connection.status == "ESTABLISHED":
            duration = time.time() - connection.create_time
            connection_durations.append(duration)

        # Identify suspicious connections based on specific criteria / Identificar conexiones sospechosas basadas en criterios específicos
        if connection.raddr.ip in suspicious_ips:
            suspicious_connections.append(connection)

        # Other analyzes and additional processing / Otros análisis y procesamiento adicional
        suspicious_ips = [...]  # List of suspicious IP addresses / Lista de direcciones IP sospechosas

        for connection in connections:
            if connection.status == "ESTABLISHED":
                established_connections += 1

            total_bytes_sent += connection.bytes_sent
            total_bytes_received += connection.bytes_recv

            # Count connections per port / Contar conexiones por puerto
            local_port = connection.laddr.port
            if local_port in connections_by_port:
                connections_by_port[local_port] += 1
            else:
                connections_by_port[local_port] = 1

            # Calculate connection duration / Calcular la duración de la conexión
            if connection.status == "ESTABLISHED":
                duration = time.time() - connection.create_time
                connection_durations.append(duration)

            # Identify suspicious connections based on specific criteria / Identificar conexiones sospechosas basadas en criterios específicos
            if connection.raddr.ip in suspicious_ips:
                suspicious_connections.append(connection)

            # Other analyzes and additional processing / Otros análisis y procesamiento adicional

    average_duration = sum(connection_durations) / len(connection_durations)

    print("Total bytes sent:", total_bytes_sent)
    print("Total bytes received:", total_bytes_received)
    print("Established connections:", established_connections)
    print("Average connection duration:", average_duration)

    print("Connections by port:")
    for port, count in connections_by_port.items():
        print(f"Port {port}: {count} connections")

    print("Suspicious connections:")
    for connection in suspicious_connections:
        print(connection)

    # Other network traffic analysis and additional processing / Otros análisis de tráfico de red y procesamiento adicional

def detect_malware(file_path):
    # signature scanning / Escaneo de firmas
    if scan_for_known_signatures(file_path):
        return True

    # heuristic analysis / Análisis heurístico
    if perform_heuristic_analysis(file_path):
        return True

    # Sandbox behavior analysis / Análisis de comportamiento en sandbox
    if run_in_sandbox(file_path):
        return True

    # metadata analysis / Análisis de metadatos
    if analyze_metadata(file_path):
        return True

    # Machine learning-based detection / Detección basada en aprendizaje automático
    if machine_learning_detection(file_path):
        return True

    # File integrity check / Verificación de integridad del archivo
    if check_file_integrity(file_path):
        return True

    return False

def scan_for_known_signatures(file_path):
    # Implement signature scanning using more advanced techniques / Implementa el escaneo de firmas utilizando técnicas más avanzadas
    # Compare the file with the known signatures / Realiza la comparación del archivo con las firmas conocidas
    # Returns True if a match is found, False otherwise / Retorna True si se encuentra una coincidencia, False en caso contrario

    known_signatures = [
    {
        'name': 'Backdoor: Win32/RemoteAdmin',
        'pattern': b'\x8B\xFF\x55\x8B\xEC\x83\xEC\x18\x53',
        'offset': 0,
        'wildcards': [b'\x00\x00'],
        'count': 1
    },
    {
        'name': 'Trojan: Win32/Stealer',
        'pattern': b'\xB9.{4}\xB8\x01\x00\x00\x00\x8B\x00\x89',
        'offset': -2,
        'wildcards': [b'\x00'],
        'count': 2
    },
    {
        'name': 'Ransomware: Win32/CryptoLocker',
        'pattern': b'\x48\x8D.{2}\x48\x8B.{2}\x33\xD2\x33',
        'offset': 0,
        'wildcards': [b'\x00'],
        'count': 3
    },
    {
        'name': 'Adware: Android/HiddenAds',
        'pattern': b'\x2F\x76\x65\x72\x69\x66\x79\x2F\x61\x6E\x64\x72\x6F\x69\x64',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Spyware: macOS/Keylogger',
        'pattern': b'\x73\x65\x6E\x64\x6B\x65\x79',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Worm: Win32/Conficker',
        'pattern': b'\x33\xC0\x8E\xD0\xBC\x00\xFB\xB8',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Rootkit: Linux/Alureon',
        'pattern': b'\x41\xFA\x0C\x13\x6C\x74\x76\x35',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Spyware: iOS/SandWorm',
        'pattern': b'\x53\x61\x6E\x64\x57\x6F\x72\x6D',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Ransomware: Android/Locker',
        'pattern': b'\x4C\x6F\x63\x6B\x65\x64\x21',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Botnet: Win32/Mirai',
        'pattern': b'\x8D\x8D\x8D\x8D\x8D\x8D\x8D\x8D',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Spyware: Win32/Keylogger',
        'pattern': b'\x68\x65\x79\x6C\x6F\x67\x67\x65\x72',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Adware: Android/AdDisplay',
        'pattern': b'\x41\x44\x44\x49\x53\x50\x4C\x41\x59',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Ransomware: Win32/WannaCry',
        'pattern': b'\x52\x5A\x20\x30\x1A\x20\x0A\x02\x00\x00\x00\x18\xE8\x89\xC1',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Rootkit: Linux/RootPipe',
        'pattern': b'\x6F\x77\x6E\x65\x72\x3D\x22\x30\x22',
        'offset': 0,
        'wildcards': [],
        'count': 1
    },
    {
        'name': 'Spyware: macOS/XRat',
        'pattern': b'\x58\x52\x61\x74',
        'offset': 0,
        'wildcards': [],
        'count': 1
    }
]

    with open(file_path, 'rb') as file:
        file_content = file.read()

        for signature in known_signatures:
            pattern = signature['pattern']
            offset = signature['offset']
            wildcards = signature['wildcards']
            count = signature['count']

            matches = re.finditer(re.escape(pattern), file_content)
            for match in matches:
                start = match.start() + offset
                end = start + len(pattern)

                if all(wc == file_content[start + i] for i, wc in enumerate(wildcards)):
                    count -= 1

                    if count == 0:
                        return True
                    
    return False

def perform_heuristic_analysis(file_path):
    # Implement heuristic analysis to detect suspicious behavior / Implementa el análisis heurístico para detectar comportamientos sospechosos
    # Look for common malware features in the file / Busca características comunes de malware en el archivo
    # Returns True if suspicious behavior is found, False otherwise / Retorna True si se encuentran comportamientos sospechosos, False en caso contrario

    # Example of basic heuristic analysis / Ejemplo de análisis heurístico básico
    suspicious_patterns = [
    "malware",
    "evil",
    "hacker",
    "eval(",
    "exec(",
    "os.system(",
    "shellcode",
    "backdoor",
    "rootkit",
    "keylogger",
    "phishing",
    "ransomware",
    "spyware",
    "trojan",
    "worm",
    "botnet",
    "exploit",
    "virus",
    "payload",
    "command injection",
    "buffer overflow",
    "SQL injection",
    "cross-site scripting",
    "remote code execution",
    "privilege escalation",
    "data exfiltration",
    "credential theft",
    "DNS hijacking",
    "ARP spoofing",
    "network scanning",
    "suspicious IP",
    "unusual network traffic",
    "unauthorized access",
    "fileless malware",
    "persistence mechanism",
    "elevated privileges",
    "registry modification",
    "root privilege escalation",
    "zero-day exploit",
    "malicious payload",
    "malicious link",
    "command and control",
    "bot herder",
    "data breach",
    "exfiltration channel",
    "stealthy behavior",
    "anti-analysis techniques",
    "polymorphic code",
    "sandbox evasion",
    "code obfuscation",
    "file encryption",
    "browser hijacking",
    "social engineering",
    "phishing email",
    "malvertising",
    "drive-by download",
    "man-in-the-middle",
    "denial of service",
    "distributed denial-of-service",
    "brute-force attack",
    "password cracking",
    "credential stuffing",
    "network intrusion",
    "web application vulnerability",
    "security misconfiguration",
    "insecure deserialization",
    "XML external entity",
    "unvalidated redirects",
    "cross-site request forgery",
    "broken access control",
    "server-side request forgery",
    "injection attacks",
    "untrusted input",
    "command injection",
    "code injection",
    "path traversal",
    "remote file inclusion",
    "security bypass",
    "file upload vulnerability",
    "code review",
    "penetration testing",
    "security assessment",
    "incident response",
    "forensic analysis",
    "security audit",
    "vulnerability scanning",
    "network monitoring",
    "log analysis",
    "anomaly detection",
    "security awareness",
    "two-factor authentication",
    "encryption algorithms",
    "secure coding practices",
    "least privilege",
    "access control",
    "firewall",
    "intrusion detection system",
    "intrusion prevention system",
    "virtual private network",
    "secure sockets layer",
    "transport layer security",
    "public key infrastructure",
    "security information and event management",
    "data loss prevention",
    "identity and access management",
    "security policies",
    "security standards",
    "patch management",
    "secure software development life cycle",
    "password policy",
    "network segmentation",
    "user awareness training"
]

    with open(file_path, 'r') as file:
        content = file.read()

        for pattern in suspicious_patterns:
            if pattern in content:
                return True

    return False

def run_in_sandbox(file_path):
    # Set up the sandbox environment / Configurar el entorno sandbox
    sandbox = pybox.Sandbox()

    try:
        # Define the file to run in the sandbox / Definir el archivo a ejecutar en el sandbox
        sandbox.execute(file_path)

        # Observe file behavior and detect malicious actions / Observar el comportamiento del archivo y detectar acciones maliciosas
        malicious_actions = []

        # Malicious action detection example: Check if suspicious files are created / Ejemplo de detección de acción maliciosa: Verificar si se crean archivos sospechosos
        if sandbox.file_created('/tmp/malicious_file.txt'):
            malicious_actions.append('Creación de archivo sospechoso')

        # Malicious Action Detection Example: Checking for Suspicious Network Connections / Ejemplo de detección de acción maliciosa: Verificar si se realizan conexiones de red sospechosas
        for connection in sandbox.network_connections():
            if connection['address'] == '192.168.0.1':
                malicious_actions.append('Conexión de red sospechosa')

    except pybox.SandboxError as e:
        # Exception handling if an error occurs in the sandbox / Manejo de excepciones si ocurre un error en el entorno sandbox
        print(f"Error en el entorno sandbox: {e}")
        return False

    finally:
        # Stopping and cleaning up the sandbox / Detener y limpiar el entorno sandbox
        sandbox.cleanup()

    # Record malicious actions detected / Registrar las acciones maliciosas detectadas
    if malicious_actions:
        print("Acciones maliciosas detectadas:")
        for action in malicious_actions:
            print(f"- {action}")
        return True

    return False

def analyze_metadata(file_path):
    suspicious = False

    # Verify the validity of the digital signature / Verificar la validez de la firma digital
    if has_valid_digital_signature(file_path):
        suspicious = True
        print("Se encontró una firma digital inválida o ausente.")

    # Analyze embedded metadata / Analizar metadatos incrustados
    embedded_metadata = extract_embedded_metadata(file_path)
    if embedded_metadata:
        analyze_embedded_metadata(embedded_metadata)

    # Parse format-specific headers / Analizar encabezados específicos del formato
    file_format = determine_file_format(file_path)
    if file_format == "PDF":
        analyze_pdf_headers(file_path)
    elif file_format == "JPEG":
        analyze_jpeg_headers(file_path)

    # Parse extended attributes / Analizar atributos extendidos
    extended_attributes = get_extended_attributes(file_path)
    if extended_attributes:
        analyze_extended_attributes(extended_attributes)

    # Verify file integrity / Verificar la integridad del archivo
    if not is_file_integrity_valid(file_path):
        suspicious = True
        print("Se detectaron cambios o manipulaciones en el archivo.")

    return suspicious

def has_valid_digital_signature(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        # Check if the file has a valid digital signature / Verificar si el archivo tiene una firma digital válida
        cert = x509.load_pem_x509_certificate(data, default_backend())
        public_key = cert.public_key()
        public_key.verify(cert.signature, data, _Padding.PKCS1v15(), cert.signature_hash_algorithm)
        return True

    except Exception as e:
        print(f"No se pudo verificar la firma digital: {e}")
        return False

def extract_embedded_metadata(file_path):
    try:
        # Run the exiftool command to extract the metadata embedded in the file / Ejecutar el comando exiftool para extraer los metadatos incrustados en el archivo
        output = subprocess.check_output(['exiftool', '-json', file_path])

        # Decode the output and convert it to a metadata dictionary / Decodificar la salida y convertirla en un diccionario de metadatos
        metadata = json.loads(output.decode('utf-8'))

        if metadata:
            return metadata[0]  # Devolver el primer diccionario de metadatos encontrado / Devolver el primer diccionario de metadatos encontrado
        else:
            return None

    except Exception as e:
        print(f"No se pudo extraer los metadatos incrustados: {e}")
        return None
    
def analyze_embedded_metadata(metadata):
    suspicious_fields = ['Author', 'Creator', 'Producer', 'Keywords', 'Subject']
    suspicious_keywords = ['malware', 'hacker', 'exploit']
    suspicious_urls = ['evilwebsite.com', 'phishingsite.com']

    suspicious_results = []

    for field in suspicious_fields:
        if field in metadata:
            value = metadata[field]
            
            # Check if the value contains suspicious keywords / Verificar si el valor contiene palabras clave sospechosas
            for keyword in suspicious_keywords:
                if keyword in value:
                    suspicious_results.append(f"Se encontró información sospechosa en el campo '{field}': {value}!")

            # Check if the value is a link to a suspicious website / Verificar si el valor es un enlace a un sitio web sospechoso
            for url in suspicious_urls:
                if url in value:
                    suspicious_results.append(f"Se encontró un enlace a un sitio web sospechoso en el campo '{field}': {value}!")

        else:
            suspicious_results.append(f"No se encontró el campo '{field}' en los metadatos.")

    # Take additional actions based on suspicious results found / Realizar acciones adicionales según los resultados sospechosos encontrados
    if suspicious_results:
        generar_alerta(suspicious_results)
        registrar_evento(suspicious_results)

    return suspicious_results

def generar_alerta(suspicious_results):
    # Configure SMTP server details / Configurar los detalles del servidor SMTP
    smtp_server = 'smtp.example.com'
    smtp_port = 587
    smtp_username = 'your_email@example.com'
    smtp_password = 'your_password'

    # Create the email content / Crear el contenido del correo electrónico
    subject = 'Alerta de seguridad: Actividad sospechosa detectada'
    body = '\n'.join(suspicious_results)
    sender = 'your_email@example.com'
    recipients = ['recipient1@example.com', 'recipient2@example.com']

    # Create the MIMEText object with the email content / Crear el objeto MIMEText con el contenido del correo electrónico
    message = MIMEText(body)
    message['Subject'] = subject
    message['From'] = sender
    message['To'] = ', '.join(recipients)

    try:
        # Establish connection to SMTP server / Establecer conexión con el servidor SMTP
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)

        # Send the email / Enviar el correo electrónico
        server.sendmail(sender, recipients, message.as_string())
        server.quit()

        print('Alerta enviada correctamente.')
    except Exception as e:
        print('Error al enviar la alerta:', str(e))

def registrar_evento(suspicious_results):
    # Define the log file name / Definir el nombre del archivo de registro
    log_file = 'event_log.txt'

    try:
        # Open log file in write mode (append) / Abrir el archivo de registro en modo de escritura (append)
        with open(log_file, 'a') as file:
            # Write suspicious results to the log file / Escribir los resultados sospechosos en el archivo de registro
            for result in suspicious_results:
                file.write(result + '\n')

        print('Evento registrado correctamente.')
    except Exception as e:
        print('Error al registrar el evento:', str(e))

def determine_file_format(file_path):
    # Create a Magic object to perform file format detection / Crear un objeto Magic para realizar la detección del formato de archivo
    file_magic = magic.Magic(mime=True)

    try:
        # Get the mime type of the file / Obtener el tipo MIME del archivo
        mime_type = file_magic.from_file(file_path)

        # Extract the file format from the MIME string / Extraer el formato de archivo de la cadena MIME
        file_format = mime_type.split('/')[-1]

        return file_format
    except Exception as e:
        print('Error al determinar el formato de archivo:', str(e))
        return None

def analyze_pdf_headers(file_path):
    try:
        # Open PDF file in binary reading mode / Abrir el archivo PDF en modo de lectura binaria
        with open(file_path, 'rb') as file:
            # Create a PdfReader object to access the content of the PDF file / Crear un objeto PdfReader para acceder al contenido del archivo PDF
            pdf_reader = PyPDF2.PdfReader(file)

            # Get the number of pages of the PDF / Obtener el número de páginas del PDF
            num_pages = len(pdf_reader.pages)

            # Get the headers of each page of the PDF / Obtener los encabezados de cada página del PDF
            headers = [page.extract_text(0, 100) for page in pdf_reader.pages]

            # Perform header analysis / Realizar el análisis de los encabezados
            suspicious_headers = []
            for header in headers:
                if 'malware' in header.lower() or 'evil' in header.lower():
                    suspicious_headers.append(header)

            # Return analysis results / Retornar los resultados del análisis
            return suspicious_headers

    except Exception as e:
        print('Error al analizar los encabezados del PDF:', str(e))
        return None

def analyze_jpeg_headers(file_path):
    try:
        # Open the JPEG file using Pillow / Abrir el archivo JPEG utilizando Pillow
        image = Image.open(file_path)

        # Get JPEG file headers / Obtener los encabezados del archivo JPEG
        exif_data = image._getexif()

        # Perform header analysis / Realizar el análisis de los encabezados
        suspicious_headers = []
        if exif_data:
            for tag, value in exif_data.items():
                if isinstance(value, str):
                    if 'malware' in value.lower() or 'evil' in value.lower():
                        suspicious_headers.append((tag, value))

        # Return analysis results / Retornar los resultados del análisis
        return suspicious_headers

    except Exception as e:
        print('Error al analizar los encabezados del JPEG:', str(e))
        return None

def get_extended_attributes(file_path):
    try:
        # Get the extended attributes of the file / Obtener los atributos extendidos del archivo
        attributes = win32api.GetExtendedAttributes(file_path)

        # Return extended attributes as a list / Retornar los atributos extendidos como una lista
        return attributes

    except Exception as e:
        print('Error al obtener los atributos extendidos del archivo:', str(e))
        return None

def analyze_extended_attributes(attributes):
    suspicious_attributes = []

    for attribute in attributes:
        if attribute.startswith('user.security'):  # Example of security related attribute / Ejemplo de atributo relacionado con la seguridad
            suspicious_attributes.append(attribute)
        elif attribute.startswith('user.hidden'):  # Example of attribute related to concealment / Ejemplo de atributo relacionado con ocultamiento
            suspicious_attributes.append(attribute)
        # Add more conditions and attributes based on your detection needs / Agrega más condiciones y atributos según tus necesidades de detección

    if suspicious_attributes:
        print('Atributos extendidos sospechosos encontrados:')
        for attribute in suspicious_attributes:
            print(attribute)

        # generate alert / Generar alerta
        generar_alerta(suspicious_attributes)

        # register event / Registrar evento
        registrar_evento(suspicious_attributes)
    else:
        print('No se encontraron atributos extendidos sospechosos.')

def is_file_integrity_valid(file_path, expected_hash):
    # Calculate the hash of the file / Calcula el hash del archivo
    file_hash = calculate_file_hash(file_path)

    # Compare the file hash with the known or expected value / Compara el hash del archivo con el valor conocido o esperado
    if file_hash == expected_hash:
        print('La integridad del archivo es válida.')
        return True
    else:
        print('La integridad del archivo es inválida.')
        return False

def calculate_file_hash(file_path):
    # Calculate the hash of the file using the SHA256 algorithm / Calcula el hash del archivo utilizando el algoritmo SHA256
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as file:
        # Read the file in blocks to handle large files / Lee el archivo en bloques para manejar archivos grandes
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)

    # Returns the computed hash in hexadecimal format / Retorna el hash calculado en formato hexadecimal
    return sha256_hash.hexdigest()

def machine_learning_detection(file_path):
    # Load the pre-trained machine learning model / Carga el modelo de aprendizaje automático previamente entrenado
    model = joblib.load('malware_detection_model.pkl')

    # Extract relevant features from the file / Extrae características relevantes del archivo
    features = extract_features(file_path)

    # Process features if necessary / Procesa las características si es necesario
    processed_features = process_features(features)

    # Makes the prediction using the machine learning model / Realiza la predicción utilizando el modelo de aprendizaje automático
    prediction = model.predict(processed_features)

    # Returns True if the prediction is malicious (1), False otherwise (0) / Retorna True si la predicción es maliciosa (1), False en caso contrario (0)
    if prediction == 1:
        print('El archivo es clasificado como malware.')
        return True
    else:
        print('El archivo no es clasificado como malware.')
        return False

def extract_features(file_path):
    # Implements the logic to extract features from the file / Implementa la lógica para extraer características del archivo
    features = []

    # Example of features: / Ejemplo de características:
    features.append(file_size(file_path))
    features.append(count_strings(file_path))
    features.append(check_file_type(file_path))

    return features

def file_size(file_path):
    # Get the size of the file in bytes / Obtener el tamaño del archivo en bytes
    size = os.path.getsize(file_path)
    return size

def count_strings(file_path):
    # Count the number of text strings in the file / Contar el número de cadenas de texto en el archivo
    count = 0
    with open(file_path, 'r') as file:
        for line in file:
            count += line.count('"')  # Count double quotes on each line / Contar las comillas dobles en cada línea
    return count

def check_file_type(file_path):
    # Check file type based on its extension / Verificar el tipo de archivo basado en su extensión
    extension = os.path.splitext(file_path)[1]
    if extension == '.txt':
        return 'Texto'
    elif extension == '.csv':
        return 'CSV'
    elif extension == '.jpg' or extension == '.png':
        return 'Imagen'
    else:
        return 'Desconocido'

def process_features(features):
    processed_features = []

    # Feature Processing Example: / Ejemplo de procesamiento de características:
    for feature in features:
        if isinstance(feature, int):
            processed_feature = normalize(feature)
        elif isinstance(feature, str):
            processed_feature = tokenize(feature)
        else:
            processed_feature = feature  # No additional processing / Sin procesamiento adicional

        processed_features.append(processed_feature)

    return processed_features

def normalize(value):
    # Normalize an integer value by dividing it by a scale factor / Normalizar un valor entero dividiéndolo por un factor de escala
    scale_factor = 1000  # Arbitrary scale factor / Factor de escala arbitrario
    normalized_value = value / scale_factor
    return normalized_value

def tokenize(text):
    # Tokenize a text by dividing it into words / Tokenizar un texto dividiéndolo en palabras
    tokens = text.split()
    return tokens
       
def analyze_with_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files, params=params)
        result = response.json()

        if 'scan_id' in result:
            scan_id = result['scan_id']
            report_url = f'https://www.virustotal.com/gui/file/{scan_id}/detection'
            print(f"Archivo enviado correctamente. Puedes ver el informe completo en: {report_url}")

            # Get the analysis result / Obtener el resultado del análisis
            analysis_result = get_analysis_result(scan_id, api_key)

            # Analyze detection results / Analizar los resultados de detección
            if analysis_result['response_code'] == 1:
                positives = analysis_result['positives']
                total = analysis_result['total']
                print(f"Detecciones positivas: {positives}/{total}")

                if positives > 0:
                    # Analyze detection results / Acciones adicionales en base a los resultados de detección
                    process_detection_results(analysis_result)
            else:
                print("Error al obtener el resultado del análisis de VirusTotal")
        elif 'error' in result:
            error_msg = result['error']['message']
            print(f"Error al enviar el archivo a VirusTotal: {error_msg}")
        else:
            print("Error desconocido al enviar el archivo a VirusTotal")

def get_analysis_result(scan_id, api_key):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': scan_id}

    response = requests.get(url, params=params)
    result = response.json()

    return result

def process_detection_results(analysis_result):
    # Analyze detection results and take further action / Analizar los resultados de detección y realizar acciones adicionales
    # For example, generating a more severe alert if detected as malicious by multiple antivirus engines / Por ejemplo, generar una alerta más grave si se detecta como malicioso por varios motores antivirus
    if analysis_result['positives'] >= 5:
        print("¡Alerta! El archivo se detectó como malicioso por múltiples motores antivirus.")
        generate_severe_alert()

    # Other additional actions / Otras acciones adicionales

def generate_severe_alert():
    # Generate a more serious alert / Generar una alerta más grave
    # For example, sending an urgent email to an administrator or locking the file / Por ejemplo, enviar un correo electrónico urgente a un administrador o bloquear el archivo
    pass

# Call the function by passing the file path and your VirusTotal API key / Llamar a la función pasando la ruta del archivo y tu clave de API de VirusTotal
analyze_with_virustotal('ruta_del_archivo', 'tu_clave_de_api')

def check_file_integrity(file_path):
    # Calculate the hash of the file and compare it to a known hash of a secure file / Calcula el hash del archivo y compáralo con un hash conocido de un archivo seguro
    # If there is a difference, return True (possible malware infection), otherwise False / Si hay alguna diferencia, retorna True (posible infección de malware), de lo contrario False
    expected_hash = get_safe_file_hash()
    file_hash = calculate_file_hash(file_path)
    return file_hash != expected_hash

def get_safe_file_hash():
    # Implements getting the known hash of a secure file / Implementa la obtención del hash conocido de un archivo seguro
    # Returns the known hash of the secure file / Retorna el hash conocido del archivo seguro
    # For example, you can query a database for known hashes or have a predefined list of hashes / Por ejemplo, puedes consultar una base de datos de hash conocidos o tener una lista predefinida de hash

    # In this example, a SHA256 hash of the safe file "safe_file.exe" is generated / En este ejemplo, se genera un hash SHA256 del archivo seguro "safe_file.exe"
    safe_file_path = 'safe_file.exe'
    block_size = 65536  # Block size for reading the file / Tamaño del bloque para la lectura del archivo

    hasher = hashlib.sha256()
    with open(safe_file_path, 'rb') as file:
        buffer = file.read(block_size)
        while len(buffer) > 0:
            hasher.update(buffer)
            buffer = file.read(block_size)

    return hasher.hexdigest()
def calculate_file_hash(file_path):
    # Calculate the hash of the file using a cryptographic algorithm (for example, SHA256) / Calcula el hash del archivo utilizando un algoritmo criptográfico (por ejemplo, SHA256)
    # Returns the hash of the file / Retorna el hash del archivo
    with open(file_path, 'rb') as file:
        data = file.read()
        file_hash = hashlib.sha256(data).hexdigest()
        return file_hash
    
def monitor_system_logs():
    # Monitor system logs and detect suspicious events / Monitorea los logs del sistema y detecta eventos sospechosos
    suspicious_events = []

    # Get System Log Records / Obtener registros de logs del sistema
    system_logs = get_system_logs()

    # Scan logs for suspicious events / Analizar los registros en busca de eventos sospechosos
    for log in system_logs:
        if is_suspicious_event(log):
            suspicious_events.append(log)

    # Take actions based on detected suspicious events / Realizar acciones basadas en eventos sospechosos detectados
    if len(suspicious_events) > 0:
        notify_security_team(suspicious_events)
        take_action(suspicious_events)

def get_system_logs():
    # Implements the logic to get the system log records / Implementa la lógica para obtener los registros de logs del sistema
    # and returns the obtained log records.              / y retorna los registros de logs obtenidos.
    system_logs = []  # Ejemplo de registros de logs obtenidos
    return system_logs

def is_suspicious_event(log):
    # Implements the logic to determine if a log event is suspicious / Implementa la lógica para determinar si un evento de log es sospechoso
    # and returns True if suspicious, False otherwise                / y retorna True si es sospechoso, False en caso contrario
    suspicious_keywords = ['hack', 'intrusion', 'unauthorized']
    for keyword in suspicious_keywords:
        if keyword in log:
            return True
    return False

def notify_security_team(events):
    # Implements logic to notify the security team about suspicious events / Implementa la lógica para notificar al equipo de seguridad sobre los eventos sospechosos
    current_time = datetime.datetime.now()
    for event in events:
        message = f"Suspicious event detected: {event} at {current_time}"
        # Code to notify the security team, e.g. send an email / Código para notificar al equipo de seguridad, por ejemplo, enviar un correo electrónico
        print(message)

def take_action(events):
    # Implements logic to take actions based on detected suspicious events / Implementa la lógica para tomar acciones basadas en los eventos sospechosos detectados
    for event in events:
        # Code to take actions, for example, block the IP associated with the event / Código para tomar acciones, por ejemplo, bloquear la IP asociada al evento
        print(f"Taking action for suspicious event: {event}")
def get_remote_hostname(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "N/A"

def get_ip_location(ip_address):
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            city = response.city.name
            country = response.country.name
            return f"{city}, {country}"
    except (FileNotFoundError, geoip2.errors.AddressNotFoundError):
        return "N/A"

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except psutil.NoSuchProcess:
        return "N/A"

def get_process_parent_info(pid):
    try:
        process = psutil.Process(pid)
        parent_pid = process.ppid()
        parent_name = get_process_name(parent_pid)
        return parent_pid, parent_name
    except psutil.NoSuchProcess:
        return None, "N/A"

def get_process_uptime(pid):
    try:
        process = psutil.Process(pid)
        create_time = process.create_time()
        uptime = time.time() - create_time
        return f"{uptime:.2f} seconds"
    except psutil.NoSuchProcess:
        return "N/A"

def get_process_file_hash(pid):
    try:
        process = psutil.Process(pid)
        executable = process.exe()
        with open(executable, 'rb') as file:
            data = file.read()
            file_hash = hashlib.sha256(data).hexdigest()
            return file_hash
    except (psutil.NoSuchProcess, FileNotFoundError):
        return "N/A"

def get_ssl_info(connection):
    if connection.status != "ESTABLISHED":
        return "N/A"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect((connection.raddr.ip, connection.raddr.port))
        cert = ssl_sock.getpeercert()
        ssl_sock.close()

        subject = dict(x[0] for x in cert["subject"])
        issuer = dict(x[0] for x in cert["issuer"])
        expiration_date = cert["notAfter"]
        
        return f"Issuer: {issuer}, Subject: {subject}, Expiration Date: {expiration_date}"
    except Exception:
        return "N/A"

def get_socket_status(connection):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((connection.laddr.ip, connection.laddr.port))
        sock.listen(1)
        sock.close()
        return "Listening"
    except Exception:
        return connection.status

def get_connection_duration(connection):
    if connection.status == "ESTABLISHED":
        duration = time.time() - connection.create_time
        return f"{duration:.2f} seconds"
    else:
        return "N/A"

def parse_netstat_output(port_filter=None, sort_by=None, connection_state=None):
    netstat_output = psutil.net_connections()
    connections = []

    for connection in netstat_output:
        if connection.status == connection_state:
            local_address = f"{connection.laddr.ip}:{connection.laddr.port}"
            remote_address = f"{connection.raddr.ip}:{connection.raddr.port}"
            remote_hostname = get_remote_hostname(connection.raddr.ip)
            ip_location = get_ip_location(connection.raddr.ip)
            process_name = get_process_name(connection.pid)
            parent_pid, parent_name = get_process_parent_info(connection.pid)
            uptime = get_process_uptime(connection.pid)
            file_hash = get_process_file_hash(connection.pid)
            ssl_info = get_ssl_info(connection)
            socket_status = get_socket_status(connection)
            connection_duration = get_connection_duration(connection)

            connections.append({
                "Local Address": local_address,
                "Remote Address": remote_address,
                "Remote Hostname": remote_hostname,
                "IP Location": ip_location,
                "Process Name": process_name,
                "Parent Process ID": parent_pid,
                "Parent Process Name": parent_name,
                "Uptime": uptime,
                "File Hash": file_hash,
                "SSL Info": ssl_info,
                "Socket Status": socket_status,
                "Connection Duration": connection_duration
            })

    # Performs connection processing and analysis / Realiza el procesamiento y análisis de las conexiones

    return connections

def load_configuration(file_path):
    # Loads the configuration from a JSON file and returns a dictionary with the configuration / Carga la configuración desde un archivo JSON y retorna un diccionario con la configuración
    with open(file_path) as f:
        config = json.load(f)
    return config

def apply_configuration(config):
    # Apply the settings to your system or application / Aplica la configuración a tu sistema o aplicación
    # Example: Assign configuration values ​​to variables or adjust system settings / Ejemplo: asigna los valores de configuración a variables o ajusta la configuración del sistema
    for key, value in config.items():
        # Example: We assume that the configuration keys are global variables and assign the values / Ejemplo: asumimos que las claves de configuración son variables globales y asignamos los valores
        globals()[key] = value

# Using the functions / Uso de las funciones
config = load_configuration("config.json")
apply_configuration(config)

def main():
    # Example of use / Ejemplo de uso
    connections = parse_netstat_output(port_filter=80, sort_by="Connection Duration", connection_state="ESTABLISHED")

    for connection in connections:
        print(connection)
        print()

def process_user_command(command):
    pass

    # User interaction / Interacción con el usuario
    print("Bienvenido al programa de monitorización.")
    while True:
        command = input("Ingrese un comando (q para salir): ")
        if command == "q":
            break
        else:
            # Process user command / Procesar el comando del usuario
            process_user_command(command)

    # Initial setup / Configuración inicial
    config = load_configuration("config.json")
    apply_configuration(config)

    # execution loop / Bucle de ejecución
    while True:
        # Perform continuous monitoring or processing tasks / Realizar tareas de monitoreo o procesamiento continuo
        monitor_resource_usage(123)
        analyze_network_traffic()
        monitor_system_logs()

        # Wait a time interval before next iteration / Esperar un intervalo de tiempo antes de la próxima iteración
        time.sleep(60)

if __name__ == "__main__":
    main()
