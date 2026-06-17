# Escáner de Red Pro - Real Time

Este proyecto es un escáner de red local desarrollado en Python con una interfaz gráfica en Tkinter.

## Características
- **Doble modo de escaneo:** Usa Scapy (ARP) o un fallback nativo (Ping + ARP Cache) si no hay Npcap.
- **Modo Turbo:** Escaneo optimizado con 100 hilos y ciclos de 5 segundos.
- **Resolución de nombres avanzada:** Identifica dispositivos mediante DNS, FQDN y NetBIOS.
- **Filtro inteligente:** Solo muestra dispositivos del rango de red actual, ignorando redes virtuales (como VMware).

## Cómo ejecutar localmente (Recomendado)
1. Instala Python 3.x.
2. Instala las dependencias: `pip install scapy`
3. Ejecuta el script: `python network_scanner.py`

## Cómo ejecutar con Docker
Ejecutar aplicaciones con interfaz gráfica (GUI) en Docker requiere un servidor X11 (como VcXsrv en Windows o XQuartz en macOS).

1. **Construir la imagen:**
   ```bash
   docker build -t escaner-red .
   ```

2. **Ejecutar el contenedor:**
   *(Requiere configurar la variable DISPLAY y usar la red del host)*
   ```bash
   docker run -it --rm \
     --network host \
     -e DISPLAY=host.docker.internal:0 \
     escaner-red
   ```

## Notas para el equipo
- El archivo `inventario_red.csv` se genera automáticamente con el historial de dispositivos.
- Consulta `DOCUMENTACION.txt` para detalles técnicos sobre el funcionamiento del código.
