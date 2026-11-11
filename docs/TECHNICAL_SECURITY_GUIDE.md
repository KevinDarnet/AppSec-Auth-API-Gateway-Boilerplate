# Guía Técnica Exhaustiva de Estudio: AppSec Auth & API Gateway Boilerplate
## Hardened Security Baseline (Node.js, Express & MongoDB)

Esta guía técnica está diseñada como un recurso de estudio exhaustivo y referencia de ingeniería en **Seguridad de Aplicaciones (AppSec)**. Detalla la arquitectura, el modelado de amenazas, las defensas implementadas y la correspondencia directa con el estándar internacional **OWASP Top 10** y las directrices **NIST SP 800-63B**.

---

## 1. Filosofía de Seguridad y Defensa en Profundidad

El paradigma de **Defensa en Profundidad (Defense in Depth)** postula que ninguna capa de seguridad individual es infalible. Por lo tanto, el sistema implementa múltiples controles defensivos superpuestos:

```
[ Cliente / Browser / Attacker ]
           │
           ▼ (1. Capa de Transporte & Red: HSTS, TLS, HTTP/2)
┌──────────────────────────────────────────────────────────────┐
│ Express Server & Security Pipeline                           │
│  ├── 2. HTTP Security Headers (Helmet, CSP, noSniff, DENY)   │
│  ├── 3. Strict CORS Whitelist (Rechazo dinámico de orígenes) │
│  ├── 4. Request Timeout (Mitigación Slowloris & DoS)         │
│  ├── 5. Body Parser Limits (10kb payload boundary)           │
│  ├── 6. Deep NoSQL Injection Sanitizer & HPP Protection     │
│  ├── 7. Multi-Tier Rate Limiting (Global & Auth Brute-Force) │
│  ├── 8. Zod Schema Validation (Strict Whitelist typing)      │
│  ├── 9. Authentication & Session Rotation (JWT + SHA-256)    │
│  ├── 10. Role-Based Access Control (RBAC & PoLP)             │
│  └── 11. Hardened Error Masking & PII-Redacted Logging       │
└──────────────────────────────────────────────────────────────┘
           │
           ▼ (12. Capa de Datos: Mongoose strictQuery, Indexing, TTL)
[ MongoDB Instance / Enclave ]
```

---

## 2. Matriz de Mitigación OWASP Top 10

| Vulnerabilidad OWASP | Riesgo Técnico | Mitigación Implementada en el Boilerplate | Archivo de Referencia |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Escalación de privilegios, manipulación de IDs (IDOR), bypass de rutas administrativas. | Middleware RBAC granular (`requireRole`, `requirePermission`), validación de sesión activa y expiración forzada por cambio de credenciales. | `src/middlewares/rbac.middleware.js` |
| **A02: Cryptographic Failures** | Almacenamiento débil de contraseñas, tokens expuestos en tránsito o base de datos. | `bcrypt` con factor de coste >= 12, tokens de refresco almacenados únicamente como hash SHA-256, comparación en tiempo constante (`timingSafeStringEqual`), HSTS activado a 1 año. | `src/core/utils/crypto.js`, `src/config/helmet.js` |
| **A03: Injection (NoSQL & Parameter)** | Inyección de operadores de consulta MongoDB (`$gt`, `$ne`, `$where`) manipulando autenticación. | Sanitización profunda y recursiva de `req.body`, `req.query`, `req.params`; validación estricta Zod; `hpp` contra Parameter Pollution; `strictQuery: true` en Mongoose. | `src/middlewares/sanitize.middleware.js`, `src/modules/auth/auth.validation.js` |
| **A04: Insecure Design** | Replay de tokens robados, ataques de stuffing masivo, ausencia de revocación. | Rotación estricta de Refresh Tokens con **Detección Automática de Reúso (Reuse Detection)** y revocación total de la familia de tokens; bloqueo de cuentas por intentos fallidos. | `src/modules/auth/auth.service.js`, `src/modules/user/user.model.js` |
| **A05: Security Misconfiguration** | Cabeceras por defecto que delatan el runtime, CORS con comodín `*`, exposición de stack traces. | Configuración estricta de `helmet`, remoción de `X-Powered-By`, CORS con lista blanca dinámica y `credentials: true` seguro, manejador de errores con enmascaramiento total en producción. | `src/config/helmet.js`, `src/config/cors.js`, `src/middlewares/error.middleware.js` |
| **A06: Vulnerable and Outdated Components** | Dependencias vulnerables a través del árbol npm. | Auditoría continua (`npm audit`), resolución de dependencias con `overrides` (0 vulnerabilidades), imágenes base Docker actualizadas (Node 22 Alpine). | `package.json`, `Dockerfile` |
| **A07: Identification and Authentication Failures** | Enumeración de usuarios, ataques de fuerza bruta, passwords débiles. | Rate limiting estricto (5 intentos / 15 min), política de contraseñas NIST (longitud, caracteres, límite seguro de 72 bytes para evitar truncamiento en bcrypt), respuestas de error genéricas y mitigación de timing side-channels. | `src/middlewares/rateLimiter.middleware.js`, `src/modules/auth/auth.service.js` |
| **A08: Software and Data Integrity Failures** | Manipulación de cabeceras de tokens JWT (algoritmo `none`), mutación no autorizada de esquemas. | Validación obligatoria de algoritmo `HS256` en `jwt.verify`, esquemas Zod con `.strict()` para rechazar Mass Assignment de campos como `role` o `isActive`. | `src/core/utils/jwt.js`, `src/modules/auth/auth.validation.js` |
| **A09: Security Logging and Monitoring Failures** | Falta de trazabilidad en incidentes, o fuga de credenciales/tokens en los logs. | Logger estructurado Winston con filtro de saneamiento que rediseña recursivamente credenciales (`password`, `token`, `cookie`), correlación distribuida mediante `X-Request-Id`. | `src/config/logger.js`, `src/middlewares/requestId.middleware.js` |
| **A10: Server-Side Request Forgery (SSRF) & Gateway Security** | Enrutamiento ciego a servicios internos no autenticados. | Gateway con autenticación de clave de API obligatoria (`X-API-Key`) mediante comparación segura `timingSafeStringEqual`, aislamiento de servicios downstream y timeout por petición. | `src/middlewares/apiKey.middleware.js`, `src/modules/gateway/gateway.routes.js` |

---

## 3. Análisis Técnico de Componentes Críticos

### 3.1. Mitigación Profunda de NoSQL Injection
En Node.js + Express con MongoDB, las consultas JSON pueden interpretar objetos anidados como selectores de consulta. Por ejemplo:
```json
POST /api/v1/auth/login
{
  "email": { "$gt": "" },
  "password": { "$ne": null }
}
```
Si el código ejecuta `UserModel.findOne({ email: req.body.email })`, la consulta evalúa `{ email: { $gt: "" } }`, devolviendo el primer usuario de la base de datos y comprometiendo el acceso.

**Defensa en el Boilerplate:**
1. **Sanitizador Recursivo (`sanitizeNoSqlPayload`)**: Recorre el payload y elimina toda clave que inicie con `$` (operadores MongoDB) o contenga `.` (navegación de rutas).
2. **Esquema Zod (`loginSchema`)**: Define `email: z.string().email()`. Un objeto `{ "$gt": "" }` falla inmediatamente la validación con error `400 Bad Request` antes de llegar a la capa de servicio o base de datos.
3. **Mongoose `strictQuery: true`**: Obliga a que los campos consultados coincidan con el esquema definido.

---

### 3.2. Criptografía y Almacenamiento de Secretos

#### Hashing de Contraseñas con `bcrypt`:
- **Factor de Trabajo (Salt Rounds >= 12)**: Produce aproximadamente 250-500 ms de cómputo por hash en hardware de servidor moderno, haciendo computacionalmente inviables los ataques masivos mediante GPUs.
- **Protección contra Truncamiento (Bcrypt Boundary)**: El algoritmo bcrypt trunca entradas superiores a 72 bytes. Si un usuario envía una contraseña de 100 caracteres, los últimos 28 son ignorados silenciosamente por implementaciones no protegidas. El esquema Zod impone `.max(72)` explícitamente para garantizar integridad criptográfica total.

#### Hashing Criptográfico de Refresh Tokens:
- **Principio**: Nunca almacenar tokens de refresco en texto plano en la base de datos.
- **Implementación**: Cuando se emite un Refresh Token, se calcula su digest `SHA-256` en el servidor:
  ```javascript
  const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  ```
- **Beneficio**: Si un atacante extrae una copia de la base de datos mediante una brecha secundaria, los tokens almacenados no pueden utilizarse para falsificar peticiones ni renovar sesiones activas.

#### Comparación en Tiempo Constante (`timingSafeStringEqual`):
Las comparaciones convencionales con `===` sufren de **Ataques de Canal Lateral por Tiempo (Timing Attacks)**: el motor de JavaScript retorna `false` en el primer byte discordante, permitiendo a un atacante inferir carácter por carácter una clave secreta midiendo microsegundos de respuesta.
El boilerplate utiliza `crypto.timingSafeEqual` con buffers de longitud equilibrada para asegurar tiempo de ejecución invariante.

---

### 3.3. Ciclo de Vida de Tokens: Rotación con Detección de Reúso (Token Reuse Detection)

Siguiendo el estándar **OAuth 2.0 Security Best Current Practice (BCP)** y **OWASP ASVS**:

```
[ Cliente Legítimo ]                                  [ Gateway / Auth Service ]
       │                                                         │
       │ 1. POST /refresh (Token A, Family-1)                    │
       ├────────────────────────────────────────────────────────►│
       │                                                         │ (Valida Token A)
       │                                                         │ (Revoca Token A)
       │                                                         │ (Genera Token B, Family-1)
       │ 2. Retorna (Token B)                                    │
       │◄────────────────────────────────────────────────────────┤
       │                                                         │
[ Atacante (interceptó Token A) ]                                │
       │                                                         │
       │ 3. POST /refresh (Token A - Ya gastado)                 │
       ├────────────────────────────────────────────────────────►│
       │                                                         │ 💥 ALERTA: ¡Reúso Detectado!
       │                                                         │ (Token A ya estaba revocado)
       │                                                         │ (ACCION: Revocar Token B y
       │                                                         │  TODA la Familia Family-1)
       │ 4. HTTP 401 Unauthorized (Sesiones invalidadas)         │
       │◄────────────────────────────────────────────────────────┤
```

**Resultado:** En cuanto el atacante o el cliente legítimo intenta usar el token anterior, el sistema detecta la discrepancia y expulsa inmediatamente todas las sesiones de esa familia, neutralizando la intrusión.

---

### 3.4. Hardening de Cabeceras HTTP (Helmet Deep Dive)

| Cabecera HTTP | Valor Configurado | Propósito de Seguridad |
| :--- | :--- | :--- |
| `Content-Security-Policy` | `default-src 'none'; base-uri 'none'; frame-ancestors 'none'` | Restricción total para APIs JSON: impide la inyección de scripts, plugins o frames en las respuestas del API. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Fuerza a los navegadores a comunicarse exclusivamente mediante HTTPS durante 1 año, incluso ante redirecciones no seguras. |
| `X-Content-Type-Options` | `nosniff` | Impide que el navegador intente adivinar el MIME-type (MIME Confusion Attacks), mitigando la ejecución de código en payloads maliciosos. |
| `X-Frame-Options` | `DENY` | Mitiga ataques de **Clickjacking**, impidiendo que la aplicación sea embebida dentro de `<iframe>` o `<frame>`. |
| `X-DNS-Prefetch-Control` | `off` | Desactiva la pre-resolución de dominios para prevenir la fuga pasiva de metadatos de enlaces y privacidad. |
| `Referrer-Policy` | `no-referrer` | Evita que tokens o parámetros sensibles en la URL viajen en la cabecera `Referer` hacia orígenes externos. |
| `X-Powered-By` | *(Eliminada)* | Suprime la divulgación del framework subyacente (evita finger-printing directo de Express). |

---

### 3.5. Lista Blanca Dinámica de CORS
- Los orígenes permitidos se declaran en variables de entorno (`CORS_ALLOWED_ORIGINS`).
- Si un origen no autorizado intenta enviar una petición con `Origin` en la cabecera, la función de callback responde con un `Error` HTTP 403 explícito.
- **Regla Crítica**: La configuración con `credentials: true` jamás debe combinarse con el comodín `origin: '*'`. El middleware valida exclusivamente contra la lista explícita.

---

### 3.6. Gestión de Errores Segura y Prevención de Fuga de Información
- **Errores Operacionales vs Errores de Programador**:
  - `AppError` encapsula errores previstos de la aplicación (400, 401, 403, 404, 429).
  - Excepciones no controladas (errores de sintaxis, fallos de conexión) son atrapadas por el manejador global.
- **Enmascaramiento en Producción**:
  - Cuando `NODE_ENV === 'production'`, el mensaje devuelto al cliente ante errores 500 es siempre genérico: `"An unexpected error occurred. Please contact support with the request ID."`
  - Jamás se devuelve `err.stack`, rutas de archivos del servidor, ni mensajes crudos de MongoDB.
  - El error real y el stack trace completo se registran internamente con el `X-Request-Id` correspondiente para análisis forense seguro.

---

### 3.7. Protección de Logs y Sanitización de PII
El logger Winston implementa un formateador de saneamiento recursivo (`scrubSensitiveData`) que enmascara automáticamente valores asociados a claves críticas:
- `password`, `token`, `accessToken`, `refreshToken`, `authorization`, `cookie`, `apiKey`, `creditCard`.
Esto asegura el cumplimiento de normativas de privacidad como **GDPR**, **PCI-DSS** y **HIPAA**.

---

## 4. Guía Práctica de Pruebas de Penetración y Verificación

Puedes verificar los controles de seguridad locales ejecutando los siguientes comandos `curl`:

### Prueba 1: Verificar Cabeceras de Seguridad y Supresión de Fingerprinting
```bash
curl -I http://localhost:4000/health/live
```
**Respuesta esperada:**
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Ausencia total de la cabecera `X-Powered-By`.

### Prueba 2: Verificar Rechazo de CORS No Autorizado
```bash
curl -i -H "Origin: http://sitio-malicioso.com" http://localhost:4000/health/live
```
**Respuesta esperada:**
- Código HTTP `403 Forbidden`.

### Prueba 3: Probar Sanitización contra Inyección NoSQL
```bash
curl -i -X POST http://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":{"$gt":""},"password":{"$ne":null}}'
```
**Respuesta esperada:**
- Código HTTP `400 Bad Request` disparado por la capa de validación Zod o sanitizador NoSQL.

### Prueba 4: Probar Límite de Tasa de Autenticación (Brute Force Defense)
Ejecutar 6 intentos seguidos de login:
```bash
for i in {1..6}; do
  curl -i -X POST http://localhost:4000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"usuario@empresa.com","password":"PasswordInvalido1!"}'
  echo "\n--- Intento $i completado ---"
done
```
**Respuesta esperada:**
- En el 6º intento, el servidor retorna `HTTP 429 Too Many Requests` con código `AUTH_RATE_LIMIT_EXCEEDED` y cabeceras `Retry-After`.

---

## 5. Guía de Inicio Rápido: Conexión de Base de Datos y Primer Arranque

Para que el servidor Express arranque en modo estricto y quede escuchando peticiones en `http://0.0.0.0:4000`, requiere una conexión activa a MongoDB. A continuación se presentan las 3 alternativas más comunes para conectarlo por primera vez:

### Opción A: MongoDB Atlas (Nube Gratuita M0 - Recomendado si no tienes Docker ni MongoDB local)
1. **Crear clúster gratuito:** Regístrate en [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) y crea un clúster gratuito (Shared M0).
2. **Crear usuario de base de datos:** En la sección **Security > Database Access**, añade un usuario con usuario y contraseña (evita caracteres especiales complejos en la contraseña o codifícalos con URL-encode).
3. **Configurar acceso de red:** En **Security > Network Access**, haz clic en **Add IP Address** y selecciona **Allow Access from Anywhere** (`0.0.0.0/0`) para desarrollo.
4. **Obtener el String de Conexión:** En **Databases**, haz clic en **Connect > Drivers**, selecciona Node.js y copia la URI generada:
   ```text
   mongodb+srv://<usuario>:<password>@cluster0.abcde.mongodb.net/appsec_gateway_db?retryWrites=true&w=majority
   ```
5. **Configurar el archivo `.env`:** Abre el archivo `.env` en la raíz del proyecto y reemplaza la variable `MONGODB_URI`:
   ```env
   MONGODB_URI=mongodb+srv://miUsuario:miPassword123@cluster0.abcde.mongodb.net/appsec_gateway_db?retryWrites=true&w=majority
   ```

---

### Opción B: Docker Compose (Recomendado si tienes Docker instalado)
El repositorio ya incluye un servicio de MongoDB 7.0 preconfigurado en el archivo `docker-compose.yml`. Para levantarlo de forma aislada en segundo plano:

```bash
docker compose up mongodb -d
```
Esto mapea automáticamente el puerto `27017` en `127.0.0.1` con almacenamiento persistente en el volumen `mongodb_data`. El valor predeterminado de `.env` (`mongodb://127.0.0.1:27017/appsec_gateway_db`) funcionará directamente.

---

### Opción C: MongoDB Local con systemd (Fedora, Ubuntu, Debian)
Si tienes instalado el paquete oficial de MongoDB en tu distribución Linux:

```bash
# Iniciar el servicio
sudo systemctl start mongod

# Habilitar para que inicie automáticamente con el sistema
sudo systemctl enable mongod

# Verificar que está activo y escuchando en el puerto 27017
sudo systemctl status mongod
```

---

### Verificación del Arranque y Primer Flujo de Uso

Una vez iniciada la base de datos (con cualquiera de las 3 opciones anteriores), ejecuta en tu terminal:

```bash
npm run dev
```

**Salida esperada en consola:**
```text
[INFO]: Initializing AppSec Auth & API Gateway Server...
[INFO]: MongoDB connected successfully to host: 127.0.0.1 (o cluster remoto)
🚀 Security Hardened Server running securely at http://0.0.0.0:4000
```

#### Paso 1: Comprobar la Sonda de Disponibilidad (Readiness Probe)
```bash
curl http://localhost:4000/health/ready
```
Respuesta esperada:
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Service is ready to handle traffic",
  "data": {
    "status": "ready",
    "database": "connected"
  }
}
```

#### Paso 2: Registrar el Primer Usuario (Register)
```bash
curl -i -X POST http://localhost:4000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@empresa.com",
    "password": "SuperP@ssword123!",
    "fullName": "Kevin Darnet"
  }'
```
Respuesta esperada: Código `201 Created` con el objeto de usuario (sin exponer el hash de contraseña).

#### Paso 3: Iniciar Sesión (Login) y Obtener Tokens
```bash
curl -i -X POST http://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@empresa.com",
    "password": "SuperP@ssword123!"
  }'
```
Respuesta esperada: Código `200 OK` retornando el `accessToken`, el `refreshToken` y la cabecera `Set-Cookie: refreshToken=...; HttpOnly; SameSite=Strict; Path=/api/v1/auth`.

#### Paso 4: Consultar el Perfil Protegido con el Bearer Token
Copia el valor de `accessToken` obtenido en el login:
```bash
curl -i http://localhost:4000/api/v1/users/me \
  -H "Authorization: Bearer <TU_ACCESS_TOKEN>"
```
Respuesta esperada: Código `200 OK` con los datos de tu usuario autenticado.

---

## 6. Resumen de Buenas Prácticas para Producción

1. **Gestión de Secretos**: Utilizar un almacén de secretos dedicado (como HashiCorp Vault, AWS Secrets Manager o Doppler) en lugar de archivos `.env` en disco.
2. **Reverse Proxy TLS**: Desplegar el servicio detrás de Nginx, Cloudflare o un Ingress Controller de Kubernetes para la terminación SSL/TLS y mitigación DDoS en capa 3/4.
3. **Contenedor No Root**: Mantener siempre la directiva `USER node` en Docker para garantizar que un potencial escape del runtime no otorgue privilegios de `root` sobre el host.
4. **Mantenimiento Continuo**: Ejecutar `npm audit` en el pipeline de CI/CD para detectar componentes vulnerables antes de su integración a producción.
