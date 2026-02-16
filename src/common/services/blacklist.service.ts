import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { createHash } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class BlacklistService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Genera hash SHA-256 del token para no almacenar el JWT original.
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Comprueba si un token está en la lista negra.
   */
  async isBlacklisted(token: string): Promise<boolean> {
    const tokenHash = this.hashToken(token);
    const record = await this.prisma.blacklistedToken.findUnique({
      where: { tokenHash },
    });
    if (!record) return false;
    if (record.expiresAt < new Date()) {
      await this.prisma.blacklistedToken.delete({ where: { id: record.id } });
      return false;
    }
    return true;
  }

  /**
   * Añade un token a la lista negra hasta su expiración.
   */
  async add(token: string, expiresAt: Date): Promise<void> {
    const tokenHash = this.hashToken(token);
    await this.prisma.blacklistedToken.upsert({
      where: { tokenHash },
      create: { tokenHash, expiresAt },
      update: { expiresAt },
    });
  }

  /**
   * Elimina tokens expirados de la tabla BlacklistedToken.
   * Se ejecuta cada hora para mantener la tabla limpia.
   */
  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredTokens(): Promise<void> {
    await this.prisma.blacklistedToken.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
  }

  /**
   * Elimina registros de rate limiting expirados (ThrottlerRecord).
   * Se ejecuta cada hora para evitar crecimiento indefinido de la tabla.
   */
  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredThrottlerRecords(): Promise<void> {
    const now = new Date();
    await this.prisma.throttlerRecord.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: now }, isBlocked: false },
          { blockExpiresAt: { not: null, lt: now } },
        ],
      },
    });
  }
}
