import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export type SecurityEvent =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'ACCOUNT_LOCKED'
  | 'PASSWORD_CHANGED'
  | 'OTP_SENT';

export type OtpChannel = 'SMS' | 'WHATSAPP';

export interface SecurityLogMeta {
  ip: string;
  userAgent: string;
  userId?: string;
  /** Canal del OTP (SMS o WHATSAPP); solo para evento OTP_SENT. */
  channel?: OtpChannel;
}

@Injectable()
export class SecurityLogService {
  private readonly logger = new Logger(SecurityLogService.name);

  constructor(private readonly prisma: PrismaService) {}

  async log(event: SecurityEvent, meta: SecurityLogMeta): Promise<void> {
    try {
      await this.prisma.securityAuditLog.create({
        data: {
          event,
          ip: meta.ip ?? 'unknown',
          userAgent: meta.userAgent ?? 'unknown',
          userId: meta.userId ?? null,
          channel: meta.channel ?? null,
        },
      });
    } catch (err) {
      this.logger.error('Error registrando auditoría', err);
    }
  }
}
