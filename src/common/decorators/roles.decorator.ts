import { SetMetadata } from '@nestjs/common';
import type { Role } from '@prisma/client';

export const ROLES_KEY = 'roles';

/**
 * Define los roles permitidos para acceder a la ruta.
 * Debe usarse junto con RolesGuard. Requiere JwtAuthGuard (autenticación previa).
 *
 * @example
 * @Roles(Role.ADMIN)
 * @Get('admin-only')
 * adminOnly() { ... }
 *
 * @Roles(Role.ADMIN, Role.USER)
 * @Get('any-authenticated')
 * anyAuth() { ... }
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
