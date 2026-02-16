import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { MessagingService } from './messaging.service';
import { OtpService } from './otp.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { BlacklistService } from '../common/services/blacklist.service';
import { SecurityLogService } from '../common/services/security-log.service';

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error(
    'JWT_SECRET no está definida. Configura la variable de entorno antes de iniciar la aplicación.',
  );
}

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: jwtSecret,
      signOptions: {
        expiresIn: Number(process.env.JWT_ACCESS_EXPIRES_IN) || 3600, // 3600 = 1h para access token
      },
    }),
  ],
  providers: [AuthService, JwtStrategy, BlacklistService, OtpService, MessagingService, SecurityLogService],
  controllers: [AuthController],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
