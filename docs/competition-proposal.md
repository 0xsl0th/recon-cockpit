# Recon Cockpit — Secure Agent Mode

Borrador técnico para el Desafío 4: seguridad de agentes inteligentes autónomos.
No presentado. Integrantes del equipo: pendiente de completar por el titular.

## Problema

Un agente que propone tareas de ciberseguridad puede interpretar instrucciones
maliciosas como órdenes, exceder el alcance autorizado o utilizar permisos
innecesarios. Delegar la decisión de seguridad al mismo agente dificulta
controlar y auditar sus acciones.

Proponemos ampliar Recon Cockpit con un plano de control independiente que
convierta propuestas estructuradas en ejecuciones limitadas, verificables y
sujetas a autorización humana cuando corresponda.

## Arquitectura

El flujo es: propuesta JSON versionada → validación estricta → política de
denegación por defecto → aprobación humana vinculada al contenido → ejecución
aislada → resultado estructurado y evento de auditoría. El agente no proporciona
comandos de shell, rutas ejecutables, archivos de salida ni modificaciones de
política. Las aprobaciones caducan y se consumen una sola vez.

El primer prototipo utiliza un proveedor simulado determinista, sin claves API,
y una sonda HTTP acotada sobre un servicio de prueba propio. En Linux, namespaces,
restricciones de filesystem, eliminación de capacidades y reglas de red limitan
la ejecución. Ante falta de aislamiento o auditoría se bloquea la ejecución; la
validación sin ejecutar continúa disponible. Los eventos JSONL admiten una futura
integración con PivotTrail sin depender de él.

## Aporte y originalidad propuesta

El aporte a evaluar es la integración de controles externos al planificador en un
flujo de reconocimiento reproducible: misma política para toda propuesta,
aprobaciones ligadas a la acción y política exactas, y verificación de alcance en
la frontera de ejecución. La demostración permite contrastar decisiones de
política con intentos reales de conexión fuera de alcance. Se utilizan mecanismos
existentes de Linux; no se afirma haber inventado el sandboxing ni demostrado
una novedad académica frente a todo el estado del arte.

## Validación y evolución

Se distinguen pruebas unitarias, integración en Linux y evidencia realmente
obtenida. Los casos incluyen destinos permitidos y bloqueados, parámetros y
herramientas inválidos, aprobaciones ausentes/caducadas/repetidas/modificadas,
límites de tiempo/salida, falta de aislamiento y fallos de auditoría. Una respuesta
maliciosa intenta inducir cambios de política o nuevas ejecuciones; el contenido
debe permanecer como datos. Estos casos no prueban inmunidad universal a prompt
injection, y el simulador no valida un modelo autónomo.

El siguiente hito incorporará acceso a destinos externos explícitamente
autorizados mediante una red administrada, preservando el filtrado por acción.
Luego se integrará un proveedor de modelo aislado y se evaluarán ataques sobre
el ciclo de planificación, presupuestos de ejecución y auditoría remota.

La convocatoria fija el 15 de noviembre de 2026 para presentar el proyecto y el
20 de mayo de 2027 para el desarrollo final. Fuente: [convocatoria oficial de la
Universidad de Palermo](https://www.palermo.edu/ingenieria/concurso-ciberseguridad/).
Antes de presentar se completarán integrantes, evidencia de ejecución en Kali,
alcance definitivo y cronograma detallado.
