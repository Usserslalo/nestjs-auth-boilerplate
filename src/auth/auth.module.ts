import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { MessagingService } from './messaging.service';
import { MockMessagingService } from './mock-messaging.service';
import { TwilioMessagingService } from './twilio-messaging.service';
import { OtpService } from './otp.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { BlacklistService } from '../common/services/blacklist.service';
import { SecurityLogService } from '../common/services/security-log.service';

function hasTwilioConfig(config: ConfigService): boolean {
  const sid = config.get<string>('TWILIO_ACCOUNT_SID');
  const token = config.get<string>('TWILIO_AUTH_TOKEN');
  const phone = config.get<string>('TWILIO_PHONE_NUMBER');
  return !!(sid?.trim() && token?.trim() && phone?.trim());
}

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: config.get<number>('JWT_ACCESS_EXPIRES_IN') ?? 3600,
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    AuthService,
    JwtStrategy,
    BlacklistService,
    OtpService,
    SecurityLogService,
    {
      provide: MessagingService,
      useFactory: (config: ConfigService) => {
        if (hasTwilioConfig(config)) {
          return new TwilioMessagingService(config);
        }
        return new MockMessagingService();
      },
      inject: [ConfigService],
    },
  ],
  controllers: [AuthController],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
