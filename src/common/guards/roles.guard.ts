import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Role } from '@prisma/client';
import { ErrorCode } from '../constants/error-codes';
import { ROLES_KEY } from '../decorators/roles.decorator';
import type { JwtValidatedUser } from '../types/auth.types';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<{ user: JwtValidatedUser }>();

    if (!user) {
      throw new ForbiddenException({
        message: 'No se pudo verificar el rol del usuario',
        errorCode: ErrorCode.AUTH_FORBIDDEN,
      });
    }

    const hasRole = requiredRoles.some((role) => user.role === role);

    if (!hasRole) {
      throw new ForbiddenException({
        message: `Acceso denegado. Se requiere uno de los siguientes roles: ${requiredRoles.join(', ')}`,
        errorCode: ErrorCode.AUTH_FORBIDDEN,
      });
    }

    return true;
  }
}
