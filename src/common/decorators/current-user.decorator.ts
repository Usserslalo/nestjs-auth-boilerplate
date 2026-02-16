import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { JwtValidatedUser } from '../types/auth.types';

/**
 * Inyecta el usuario autenticado (payload del JWT) en el handler.
 * Requiere JwtAuthGuard en la ruta (o como guard global).
 *
 * @example
 * @Get('me')
 * getMe(@CurrentUser() user: JwtValidatedUser) {
 *   return user; // { userId, email, role }
 * }
 *
 * @Get('my-id')
 * getId(@CurrentUser('userId') userId: string) {
 *   return { id: userId };
 * }
 */
export const CurrentUser = createParamDecorator(
  (data: keyof JwtValidatedUser | undefined, ctx: ExecutionContext): JwtValidatedUser | string => {
    const request = ctx.switchToHttp().getRequest<{ user: JwtValidatedUser }>();
    const user = request.user;

    if (data) {
      return user[data];
    }

    return user;
  },
);
