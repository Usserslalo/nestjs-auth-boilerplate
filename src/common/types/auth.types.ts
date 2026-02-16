import type { Role } from '@prisma/client';

/**
 * Usuario validado por JWT (payload del token).
 * Usado por @CurrentUser y RolesGuard.
 */
export interface JwtValidatedUser {
  userId: string;
  email: string;
  role: Role;
}
