# 🚀 NestJS Ultra-Secure Auth Boilerplate

[![NestJS](https://img.shields.io/badge/NestJS-11-E0234E?logo=nestjs&logoColor=white)](https://nestjs.com/)
[![Prisma](https://img.shields.io/badge/Prisma-7-2D3748?logo=prisma&logoColor=white)](https://www.prisma.io/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-UNLICENSED-lightgrey)](./LICENSE)

> **Production-Ready** — Plantilla de autenticación y autorización diseñada para **escalabilidad** y **máxima seguridad**. Ideal para APIs, SaaS y backends que exigen estándares empresariales, auditoría trazable y cero concesiones en identidad y resiliencia.

---

## 📋 Tabla de contenidos

- [Propuesta de valor](#-propuesta-de-valor)
- [Core Features](#-core-features)
- [Tech Stack](#-tech-stack)
- [Arquitectura de errores (RFC 7807)](#-arquitectura-de-errores-rfc-7807)
- [Guía de inicio rápido](#-guía-de-inicio-rápido)
- [Documentación de API](#-documentación-de-api)
- [Modo desarrollo vs producción](#-modo-desarrollo-vs-producción)
- [Licencia](#-licencia)

---

## 💎 Propuesta de valor

Este **boilerplate** no es un prototipo: es **infraestructura de producción**. Ofrece una base reutilizable con:

- **Seguridad por defecto**: JWT con secretos independientes (Access/Refresh), rotación de tokens, OTP por SMS/WhatsApp, bloqueo por fuerza bruta y rate limiting persistente.
- **Datos limpios y consistentes**: Sanitización automática en DTOs (trim, lowercase en emails), validación estricta y errores estándar (RFC 7807).
- **Panel de administración**: Gestión de usuarios con paginación real, filtros dinámicos y auditoría imborrable de acciones administrativas.
- **Resiliencia**: Headers `Retry-After` en 429, throttling por ruta y registro de eventos de seguridad en base de datos.

Construye tu producto sobre una base que ya cumple con buenas prácticas de seguridad y mantenibilidad.

---

## ✨ Core Features

| Área | Característica | Descripción |
|------|----------------|-------------|
| 🔐 **Seguridad Pro** | JWT dual (Access + Refresh) | Secretos independientes; Access 1h, Refresh 7d. Rotación de `jti` en cada refresh; logout invalida sesión en BD. |
| 🔐 **Seguridad Pro** | Contraseñas | Hash con **Argon2id** (64 MiB, 2 iteraciones). Nunca se exponen en respuestas ni logs. |
| 🆔 **Identidad** | OTP vía SMS/WhatsApp | Integración **Twilio**; códigos de 6 dígitos con expiración configurable. Verificación de cuenta y recuperación de contraseña. |
| 🆔 **Identidad** | Mock para desarrollo | Sin credenciales Twilio: **MockMessagingService** imprime códigos en consola para trabajar offline. |
| 📊 **Gestión de datos** | Prisma 7 + PostgreSQL | ORM con Driver Adapter; migraciones versionadas; modelo User + VerificationCode, Blacklist, Throttler, SecurityAuditLog. |
| 📊 **Gestión de datos** | Sanitización automática | Emails: `trim` + `toLowerCase`. Teléfonos y búsquedas: `trim`. ValidationPipe con `transform: true`. |
| 👥 **Panel de administración** | Gestión de usuarios | Listado paginado, filtros por rol, estado y verificación; búsqueda insensible a mayúsculas en email/teléfono; ordenamiento configurable. |
| 👥 **Panel de administración** | Acciones administrativas | Activar/desactivar usuario (banear); cambiar rol (ADMIN/USER). Auditoría con adminId, targetUserId, requestId en `SecurityAuditLog`. |
| 🛡️ **Resiliencia** | Rate limiting persistente | Throttler con almacenamiento en PostgreSQL; límites por ruta (ej. 5/min en login, verify, reset-password). |
| 🛡️ **Resiliencia** | Bloqueo por fuerza bruta | 5 intentos fallidos de login → cuenta bloqueada 15 min. Eventos `LOGIN_FAILED` y `ACCOUNT_LOCKED` en auditoría. |
| 🛡️ **Resiliencia** | Headers Retry-After | En respuestas 429 se incluye `Retry-After` (segundos) para que el cliente sepa cuándo reintentar. |
| 📜 **Auditoría** | Eventos de seguridad | `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `PASSWORD_CHANGED`, `OTP_SENT`. |
| 📜 **Auditoría** | Acciones administrativas | `ADMIN_USER_STATUS_CHANGE` y `ADMIN_USER_ROLE_CHANGE` con metadata (adminId, targetUserId, newStatus/oldRole/newRole, requestId). |

---

## 🛠 Tech Stack

| Tecnología | Uso |
|------------|-----|
| **NestJS 11** | Framework backend, módulos, guards, interceptors, pipes. |
| **Prisma 7** | ORM con Driver Adapter para PostgreSQL. |
| **PostgreSQL** | Base de datos principal. |
| **Argon2** | Hash de contraseñas (argon2id). |
| **Zod** | Validación de variables de entorno al arranque. |
| **Twilio SDK** | Envío de SMS/WhatsApp para OTP (opcional; Mock si no hay credenciales). |
| **@nestjs/jwt** | Emisión y verificación de Access y Refresh tokens. |
| **Passport + JWT** | Estrategia de autenticación para rutas protegidas. |
| **class-validator / class-transformer** | Validación y transformación de DTOs. |
| **Swagger (OpenAPI)** | Documentación interactiva en `/docs`. |
| **Helmet + compression** | Seguridad de cabeceras HTTP y compresión de respuestas. |

---

## 📐 Arquitectura de errores (RFC 7807)

Todas las respuestas **4xx y 5xx** siguen un formato estándar tipo **RFC 7807**: mismo esquema JSON, códigos de error claros y trazabilidad con `requestId` y cabecera `X-Request-ID`.

### Ejemplo de respuesta de error

```json
{
  "success": false,
  "statusCode": 400,
  "errorCode": "BAD_REQUEST",
  "message": "El email debe ser un correo válido",
  "path": "/api/auth/login",
  "timestamp": "2026-02-16T12:00:00.000Z",
  "requestId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "errors": [
    "email must be an email",
    "password must be longer than or equal to 6 characters"
  ]
}
```

| Campo | Descripción |
|-------|-------------|
| `statusCode` | Código HTTP (400, 401, 403, 404, 409, 422, 429, 500). |
| `errorCode` | Slug interno (ej. `AUTH_UNAUTHORIZED`, `RATE_LIMIT_EXCEEDED`, `NOT_FOUND`). |
| `message` | Mensaje legible; en auth se evita user enumeration. |
| `path` | Ruta de la petición. |
| `timestamp` | ISO 8601. |
| `requestId` | ID único de la petición (también en cabecera). |
| `errors` | Opcional; detalle por campo en errores de validación. |

---

## 🏁 Guía de inicio rápido

### 1. Instalación

```bash
git clone <repo>
cd nestjs-auth-boilerplate
npm install
```

### 2. Configuración de entorno

Copia el archivo de ejemplo y configura las variables críticas (nunca subas `.env` al repositorio):

```bash
cp .env.example .env
```

Variables críticas:

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `DATABASE_URL` | ✅ | URL de PostgreSQL (ej. `postgresql://user:pass@localhost:5432/auth_db`) |
| `JWT_SECRET` | ✅ | Secreto para Access token (mín. 32 caracteres). Ej: `openssl rand -base64 32` |
| `JWT_REFRESH_SECRET` | ✅ | Secreto distinto para Refresh token (mín. 32 caracteres). |
| `JWT_ACCESS_EXPIRES_IN` | No | Segundos de vida del Access token (default: 3600). |
| `JWT_REFRESH_EXPIRES_IN` | No | Segundos de vida del Refresh token (default: 2592000). |
| `PORT` | No | Puerto del servidor (default: 3000). |
| `TWILIO_*` | No | Si están vacías, se usa **MockMessagingService** (códigos en consola). |

### 3. Base de datos: migraciones y seed

Aplicar migraciones (Prisma 7):

```bash
npx prisma migrate dev
```

Cargar usuario de prueba (ADMIN, verificado):

```bash
npx prisma db seed
```

Credenciales por defecto: **admin@example.com** / **Admin#123**.

### 4. Arrancar la aplicación

```bash
# Desarrollo (watch)
npm run start:dev

# Producción
npm run build
npm run start:prod
```

- **API base**: `http://localhost:3000/api`
- **Documentación**: `http://localhost:3000/docs`

---

## 📚 Documentación de API

La API está documentada en **OpenAPI (Swagger)** en:

```
http://localhost:3000/docs
```

- Endpoints de auth (login, register, verify-whatsapp, refresh, logout, change-password, resend-otp, forgot-password, reset-password, me).
- Endpoints de administración (listar usuarios, cambiar estado, cambiar rol).
- Uso del botón **Authorize**: introduce el `access_token` devuelto por `POST /auth/login` (formato Bearer) para probar rutas protegidas y de admin.
- Códigos de respuesta documentados: 200, 201, 400, 401, 403, 404, 409, 422, 429, 500.

---

## 🔄 Modo desarrollo vs producción

| Aspecto | Desarrollo | Producción |
|---------|------------|------------|
| **Mensajería OTP** | Si `TWILIO_*` están vacías → **MockMessagingService**: los códigos se imprimen en la consola del servidor. Permite trabajar sin credenciales Twilio. | Configura `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` y `TWILIO_PHONE_NUMBER` para envío real por SMS/WhatsApp. |
| **CORS** | Por defecto se permiten orígenes locales (ej. `localhost:3000`, `localhost:5173`). | Define `CORS_ORIGINS` con los dominios permitidos, separados por comas. |
| **Secrets** | Puedes usar valores de ejemplo solo en local. | Usa secretos largos y aleatorios; nunca los subas al repositorio. |

---

## 📁 Estructura del módulo de autenticación

```
src/
├── auth/
│   ├── auth.controller.ts    # Endpoints públicos y protegidos
│   ├── auth.service.ts       # Lógica: tokens, OTP, cambio de contraseña, perfil
│   ├── auth.module.ts        # JwtModule, PassportModule, SecurityLogService
│   ├── constants/roles.ts    # ROLES (ADMIN, USER)
│   ├── dto/                  # LoginDto, RegisterDto, VerifyWhatsAppDto, etc.
│   ├── guards/               # JwtAuthGuard, RolesGuard
│   ├── strategies/           # JwtStrategy
│   └── ...
├── admin/
│   ├── admin-users.service.ts
│   ├── users.controller.ts  # GET/PATCH usuarios (solo ADMIN)
│   └── dto/
├── common/
│   ├── services/security-log.service.ts  # Auditoría
│   ├── dto/rfc7807-error.dto.ts
│   ├── filters/              # PrismaClientException, HttpException
│   └── ...
└── prisma/
    ├── schema.prisma
    └── migrations/
```

---

## 📜 Licencia

**UNLICENSED** (proyecto privado). Ajustar según la política de tu organización.
