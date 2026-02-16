import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Marca una ruta como pública (no requiere JWT).
 * Usar en login, register, verify-otp, forgot-password, reset-password, refresh, resend-otp.
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
