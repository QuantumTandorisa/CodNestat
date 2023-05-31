Readme

Este proyecto es una colección de utilidades y herramientas para el análisis de seguridad y gestión de recursos en diferentes sistemas operativos.

Requisitos previos

Antes de ejecutar este proyecto, asegúrate de cumplir con los siguientes requisitos:

    Python 3.7 o superior
    Bibliotecas adicionales: pybox, cryptography, exiftool, pyopenssl, smtplib
    Las dependencias externas necesarias están especificadas en el archivo requirements.txt

Instalación

Sigue estos pasos para instalar el proyecto en tu máquina local:

    Clona este repositorio en tu máquina local.
    Accede al directorio del proyecto: cd proyecto-analisis-seguridad.
    Crea un entorno virtual: python3 -m venv venv.
    Activa el entorno virtual:
        En Windows: venv\Scripts\activate.
        En macOS/Linux: source venv/bin/activate.
    Instala las dependencias del proyecto: pip install -r requirements.txt.

Uso
Analizar el tráfico de red

El archivo analyze_network_traffic.py contiene funciones para analizar el tráfico de red. Para ejecutar el análisis, sigue estos pasos:

    Asegúrate de tener privilegios de administrador en tu sistema operativo.
    Ejecuta el archivo analyze_network_traffic.py:

python analyze_network_traffic.py

Observa los resultados en la consola. El análisis incluye escaneo de firmas, análisis heurístico, análisis de comportamiento en sandbox, análisis de metadatos y detección basada en aprendizaje automático.

Para utilizar el programa de análisis de archivos, se deben cumplir los requisitos mencionados anteriormente. Luego, se pueden llamar a las funciones según sea necesario, pasando la ruta del archivo a analizar como argumento.

    file_path = '/ruta/al/archivo'
    result = perform_heuristic_analysis(file_path)
    print(result)

El programa imprimirá True si se detecta actividad sospechosa en el archivo, y False en caso contrario.

Nota: Tene en cuenta que debes modificar el codigo segun los datos que obtengas y las funciones que deseas utilizar, correspondiente a las variables que estan esperando los datos necesarios para su correcto funcionamiento.
