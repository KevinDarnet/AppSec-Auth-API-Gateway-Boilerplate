# AppSec Auth & API Gateway Boilerplate
> **Hardened Security Baseline** para aplicaciones de misión crítica en Node.js, Express y MongoDB.
> Diseñado bajo el principio de **Defensa en Profundidad** y alineado a las directrices de **OWASP Top 10** y **NIST SP 800-63B**.

---

## 🛡️ Características Principales de Seguridad

- **Cabeceras HTTP Estrictas (`helmet`)**: Configuración exhaustiva con HSTS (1 año + preload), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, control de prefetch DNS, Content Security Policy para APIs y supresión de `X-Powered-By`.
- **CORS Dinámico con Lista Blanca**: Rechazo estricto de orígenes no autorizados sin recurrir a comodines (`*`) con soporte seguro para `credentials: true`.
- **Rate Limiting Multinivel (`express-rate-limit`)**:
  - Limitador global volumétrico contra ataques de denegación de servicio.
  - Limitador estricto para rutas de autenticación (prevención de ataques de fuerza bruta, credential stuffing y pulverización de contraseñas).
  - Limitador de acciones sensibles (cambio de contraseña, refresco de sesión).
- **Prevención Profunda de NoSQL Injection**:
  - Sanitizador recursivo en `req.body`, `req.query` y `req.params` neutralizando selectores de MongoDB (`$gt`, `$ne`, `$regex`, `$where`) y rutas anidadas manipuladas.
  - Esquemas de validación estrictos con **Zod** (`.strict()`) que neutralizan ataques de **Mass Assignment**.
  - `strictQuery: true` configurado a nivel de Mongoose.
- **Protección contra Parameter Pollution (`hpp`)**: Rechazo de manipulación de arrays en parámetros de consulta.
- **Autenticación Robusta & Ciclo de Vida de Tokens**:
  - Hashing seguro de contraseñas con **`bcrypt` (factor de coste salt rounds >= 12)** y límite de 72 bytes contra truncamiento.
  - **Tokens de Acceso de corta duración** firmados con HMAC-SHA256 (`HS256`) y validación explícita de algoritmos (mitigación de ataque `alg: none`).
  - **Rotación de Refresh Tokens con Detección Automática de Reúso (Token Reuse Detection)**: Si se intenta reusar un token de refresco gastado o revocado, se invalida de forma inmediata la familia completa de sesiones para neutralizar el robo de credenciales.
  - Almacenamiento seguro de Refresh Tokens: en la base de datos se almacena exclusivamente el **hash SHA-256** del token, nunca el token en texto plano.
  - Cookies con atributos `HttpOnly`, `Secure`, `SameSite: Strict` y ámbito delimitado a `/api/v1/auth`.
- **Control de Acceso Basado en Roles (RBAC)**: Enfoque de menor privilegio (Principio de Menor Privilegio) con roles (`user`, `moderator`, `admin`) y permisos granulares.
- **API Gateway Integrado**:
  - Validación de claves de API (`X-API-Key`) mediante comparación en tiempo constante (`crypto.timingSafeEqual`) contra ataques de canal lateral (Timing Attacks).
  - Trazabilidad y correlación distribuida con identificador único `X-Request-Id` (UUID v4).
  - Control de tiempo de espera (`timeout`) para mitigar ataques de conexión lenta (Slowloris).
- **Manejo Centralizado de Errores & Logging Seguro**:
  - Cero fuga de stack traces, rutas internas o detalles de base de datos en entornos de producción.
  - Logger estructurado (**Winston**) con saneamiento automático y recursivo de información sensible y PII (`password`, `token`, `cookie`, `creditCard`).
- **Contenedor Docker Hardened**:
  - Construcción multi-stage en base a Node 22 Alpine.
  - Ejecución bajo usuario sin privilegios `USER node` (no-root).
  - Sondas de salud integradas (`/health/live`, `/health/ready`).

---

## 📁 Estructura del Proyecto

```
appsec-auth-gateway-boilerplate/
├── .dockerignore
├── .env.example                  # Plantilla documentada de variables de entorno
├── .gitignore
├── Dockerfile                    # Contenedor hardened multi-stage con usuario no-root
├── docker-compose.yml            # Orquestación con App + MongoDB y resource limits
├── package.json                  # Dependencias con 0 vulnerabilidades auditadas
├── README.md
├── docs/
│   └── TECHNICAL_SECURITY_GUIDE.md  # Guía técnica exhaustiva de estudio
├── src/
│   ├── config/
│   │   ├── env.js                # Validación estricta y fail-fast de variables de entorno
│   │   ├── database.js           # Conexión Mongoose hardened y connection pooling
│   │   ├── helmet.js             # Cabeceras de seguridad HTTP
│   │   ├── cors.js               # Lista blanca dinámica de CORS
│   │   └── logger.js             # Winston estructurado con saneamiento de secretos
│   ├── core/
│   │   ├── errors/
│   │   │   ├── AppError.js       # Errores operacionales tipados
│   │   │   └── errorCodes.js     # Códigos estándar de error AppSec
│   │   ├── constants/
│   │   │   └── roles.js          # Definiciones RBAC y matriz de permisos
│   │   └── utils/
│   │       ├── crypto.js         # bcrypt >= 12, timingSafeEqual, SHA-256 tokens
│   │       ├── jwt.js            # Firma y verificación con validación estricta de algoritmos
│   │       └── response.js       # Formato estándar predecible de respuesta API
│   ├── middlewares/
│   │   ├── requestId.middleware.js   # Correlación de trazas X-Request-Id
│   │   ├── sanitize.middleware.js    # Sanitizador NoSQL Injection y HPP
│   │   ├── rateLimiter.middleware.js # Limitadores de tasa global y de autenticación
│   │   ├── validate.middleware.js    # Validación de esquemas Zod (body, query, params)
│   │   ├── auth.middleware.js        # Verificación de JWT y estado activo de la cuenta
│   │   ├── rbac.middleware.js        # Control de roles y permisos
│   │   ├── apiKey.middleware.js      # Validación segura de API Key para el Gateway
│   │   ├── timeout.middleware.js     # Tiempo máximo de ejecución de peticiones
│   │   └── error.middleware.js       # Manejador centralizado sin fuga de información
│   ├── modules/
│   │   ├── auth/                 # Registro, Login, Refresh rotativo, Logout, Revocación
│   │   ├── user/                 # Perfil, cambio de password, administración de usuarios
│   │   ├── session/              # Modelo de Refresh Tokens con TTL Index
│   │   ├── gateway/              # Enrutador y proxy seguro del Gateway
│   │   └── health/               # Sondas de liveness y readiness
│   ├── app.js                    # Pipeline defensivo Express
│   └── server.js                 # Inicialización, señales de apagado elegante (graceful shutdown)
└── tests/
    └── security.test.js          # Suite automatizada de pruebas de seguridad (node:test)
```

---

## 🚀 Inicio Rápido

### Prerrequisitos
- **Node.js**: v20+ o v22+
- **MongoDB**: v6.0+ o v7.0+ (local o en Docker)

### 1. Clonar e Instalar Dependencias
```bash
git clone <tu-repositorio>
cd appsec-auth-gateway-boilerplate
npm install
```

### 2. Configurar Base de Datos y Variables de Entorno
Copia la plantilla `.env.example` a `.env`:
```bash
cp .env.example .env
```

Para conectar MongoDB por primera vez, elige cualquiera de estas 3 opciones:

- **Opción A (MongoDB Atlas - Nube Gratuita):**
  Crea un clúster gratis en [MongoDB Atlas](https://www.mongodb.com/cloud/atlas), habilita acceso de red (`0.0.0.0/0` para desarrollo) y pega tu URI en el `.env`:
  ```env
  MONGODB_URI=mongodb+srv://<usuario>:<password>@cluster0.abcde.mongodb.net/appsec_gateway_db?retryWrites=true&w=majority
  ```

- **Opción B (Docker Compose):**
  Levanta el contenedor de MongoDB 7.0 preconfigurado:
  ```bash
  docker compose up mongodb -d
  ```

- **Opción C (MongoDB Local con systemd en Linux):**
  ```bash
  sudo systemctl start mongod
  ```

### 3. Ejecutar en Modo Desarrollo
```bash
npm run dev
```

El servidor iniciará mostrando:
```text
[INFO]: Initializing AppSec Auth & API Gateway Server...
[INFO]: MongoDB connected successfully to host: ...
🚀 Security Hardened Server running securely at http://0.0.0.0:4000
```

### 4. Verificar el Estado del Servidor
Comprueba que el servidor y la base de datos están listos:
```bash
curl http://localhost:4000/health/ready
```

### 5. Ejecutar la Suite de Pruebas de Seguridad
```bash
npm test
```
Ejecuta las 9 pruebas unitarias y de integración que verifican bcrypt, JWT, sanitización NoSQL, esquemas Zod, cabeceras Helmet y CORS.

---

## 🐳 Despliegue con Docker y Docker Compose

El proyecto incluye configuración para levantar tanto la base de datos MongoDB como el servidor Node.js en una red aislada y segura:

```bash
docker compose up --build -d
```

Verificar el estado del servicio:
```bash
docker compose ps
curl http://localhost:4000/health/ready
```

Detener los contenedores:
```bash
docker compose down
```

---

## 📡 Referencia de Endpoints del API

### Rutas de Salud e Infraestructura
| Método | Endpoint | Descripción | Autenticación |
| :--- | :--- | :--- | :--- |
| `GET` | `/health/live` | Sonda de vida (Liveness Probe) | Pública |
| `GET` | `/health/ready` | Sonda de disponibilidad (Readiness Probe, valida MongoDB) | Pública |

### Módulo de Autenticación (`/api/v1/auth`)
| Método | Endpoint | Descripción | Controles de Seguridad |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Registro de nuevo usuario | Auth Rate Limit, validación Zod contra Mass Assignment |
| `POST` | `/api/v1/auth/login` | Inicio de sesión y expedición de tokens | Auth Rate Limit (5/15m), bloqueo tras intentos fallidos, cookie HttpOnly |
| `POST` | `/api/v1/auth/refresh` | Renovación y rotación de tokens | Detección automática de reúso, Sensitive Rate Limit |
| `POST` | `/api/v1/auth/logout` | Cierre de sesión individual | Invalida el refresh token en base de datos y borra cookie |
| `POST` | `/api/v1/auth/revoke-all`| Revocación global de sesiones activas | Requiere JWT válido |

### Módulo de Usuarios (`/api/v1/users`)
| Método | Endpoint | Descripción | Control de Acceso |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/users/me` | Obtener perfil del usuario autenticado | Token JWT (`Bearer` o Cookie) |
| `PATCH` | `/api/v1/users/me` | Actualizar nombre del perfil | Token JWT + Zod Whitelist |
| `POST` | `/api/v1/users/me/change-password` | Cambio de contraseña | Token JWT + verificación de contraseña actual |
| `GET` | `/api/v1/users` | Listar todos los usuarios con paginación | Rol `admin` |
| `PATCH` | `/api/v1/users/:id` | Modificar rol o activar/desactivar cuenta | Rol `admin` + Zod |

### Módulo de API Gateway (`/api/v1/gateway`)
| Método | Endpoint | Descripción | Control de Acceso |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/gateway/status` | Estado del gateway y servicios registrados | `X-API-Key` (Timing-safe) |
| `ALL` | `/api/v1/gateway/proxy/service-mock` | Enrutamiento a downstream interno | `X-API-Key` obligatorio |
| `GET` | `/api/v1/gateway/admin/registry` | Gestión administrativa del gateway | Rol `admin` JWT |

---

## 📚 Guía Técnica de Estudio
Para un análisis técnico exhaustivo que cubra:
- Modelado de amenazas y mitigaciones detalladas contra el **OWASP Top 10**.
- Diagramas de secuencia de **Token Rotation con Reuse Detection**.
- Pruebas prácticas con comandos `curl` para auditoría y penetration testing.

Consulta el documento en: **[`docs/TECHNICAL_SECURITY_GUIDE.md`](file:///home/kevindarnet/.gemini/antigravity/scratch/appsec-auth-gateway-boilerplate/docs/TECHNICAL_SECURITY_GUIDE.md)**.

---

## 📄 Licencia
Este proyecto se distribuye bajo la licencia **MIT**. Diseñado con fines educativos y de arquitectura para la construcción de backends seguros.
# AppSec-Auth-API-Gateway-Boilerplate
