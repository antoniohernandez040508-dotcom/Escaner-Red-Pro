# Usar una imagen base de Python ligera
FROM python:3.11-slim

# Instalar dependencias del sistema necesarias para Tkinter y herramientas de red
RUN apt-get update && apt-get install -y \
    python3-tk \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Crear y establecer el directorio de trabajo
WORKDIR /app

# Copiar los archivos del proyecto al contenedor
COPY network_scanner.py .
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Comando para ejecutar la aplicación
# Nota: Requiere configuración de X11 en el host para mostrar la GUI
CMD ["python", "network_scanner.py"]
