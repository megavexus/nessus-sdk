# Base de Argos Observer

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