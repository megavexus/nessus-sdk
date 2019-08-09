# Base de Argos Observer
## [v1.1.0]
# Changed
- Se ha cambiado el modelo de la api

# Added
- [WIP] Añadida API de Security Center con capacidades de crear, lanzar escaneos y programarlos.
- [WIP] Añadida API de Security Center con capacidades de parar, reanudar y detener escaneos.


## [v1.0.1]
# Added
- Añadida API de Security Center con capacidades para inspeccionar escaneos

## [v0.3.1]
### FIXED
- Bug al sacar resultados en forma de eventos.

### CHANGED
- Añadidos datos del OS a los eventos de splunk

### ADEDD
- Capacidad para aceptar listas de targets.


## [v0.2.0]
### ADDED
- Método para crear e iniciar un scaneo la información de un escaneo en forma de diccionario
- Método para actualizar los targets de un escaneo.
- Control de flujo de ejecución de un escaneo.
- Añadido logger
- Añadido método para esperar a que un scan acabe
- Método para sacar la información de un escaneo en forma de diccionario
- Método para obtener la información de escaneo en forma de eventos string para Splunk
- Método para obtener el diferencial de dos escaneos

### CHANGED
- Se ha cambiado el acceso a ness6rest de herencia a composición, para permitir mayor aislamiento

## [v0.1]
- Creada versión de SDK que permite ignorar los problemas de certificados
- Añadidas funcionalidades para parar escaneos