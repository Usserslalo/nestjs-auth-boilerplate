import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ErrorCode } from '../../common/constants/error-codes';
import type { JwtValidatedUser } from '../../common/types/auth.types';
import { BlacklistService } from '../../common/services/blacklist.service';
import { AuthService, JwtPayload } from '../auth.service';

export type { JwtValidatedUser };

const extractBearerToken = ExtractJwt.fromAuthHeaderAsBearerToken();

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly authService: AuthService,
    private readonly blacklistService: BlacklistService,
    config: ConfigService,
  ) {
    super({
      jwtFromRequest: extractBearerToken,
      ignoreExpiration: false,
      secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JwtPayload): Promise<JwtValidatedUser> {
    const token = extractBearerToken(req);
    if (token) {
      const isBlacklisted = await this.blacklistService.isBlacklisted(token);
      if (isBlacklisted) {
        throw new UnauthorizedException({
          message: 'Token revocado. Inicie sesión de nuevo.',
          errorCode: ErrorCode.AUTH_TOKEN_REVOKED,
        });
      }
    }

    const user = await this.authService.validateUserById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado o inactivo');
    }

    return {
      userId: user.id,
      email: user.email,
      role: user.role,
    };
  }
}
