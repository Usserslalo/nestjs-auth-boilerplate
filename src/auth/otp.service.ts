import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ThrottlerException } from '@nestjs/throttler';
import { VerificationCodeType } from '@prisma/client';
import { createHash, randomInt } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';

const OTP_LENGTH = 6;
const OTP_EXPIRES_MINUTES = 10;
const MAX_ATTEMPTS = 3;
const RESEND_COOLDOWN_MS = 2 * 60 * 1000; // 2 minutos

@Injectable()
export class OtpService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Genera un código OTP numérico de 6 dígitos.
   */
  generate(): string {
    const min = 10 ** (OTP_LENGTH - 1);
    const max = 10 ** OTP_LENGTH - 1;
    return randomInt(min, max + 1).toString();
  }

  /**
   * Hashea el código con SHA-256 para no almacenarlo en texto plano.
   */
  hashCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  /**
   * Comprueba si el usuario puede solicitar un nuevo código (cooldown de 2 min).
   */
  private async checkCooldown(userId: string, type: VerificationCodeType): Promise<void> {
    const last = await this.prisma.verificationCode.findFirst({
      where: { userId, type },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    });
    if (last) {
      const elapsed = Date.now() - last.createdAt.getTime();
      if (elapsed < RESEND_COOLDOWN_MS) {
        const waitSec = Math.ceil((RESEND_COOLDOWN_MS - elapsed) / 1000);
        throw new ThrottlerException(
          `Espere ${waitSec} segundos antes de solicitar un nuevo código.`,
        );
      }
    }
  }

  /**
   * Crea un código OTP para el usuario (registro o password reset).
   * Aplica cooldown de 2 minutos. Invalida códigos anteriores del mismo tipo.
   * Retorna el código en texto plano para enviarlo por mensajería.
   */
  async create(userId: string, type: VerificationCodeType): Promise<string> {
    await this.checkCooldown(userId, type);

    await this.prisma.verificationCode.deleteMany({
      where: { userId, type },
    });

    const code = this.generate();
    const codeHash = this.hashCode(code);
    const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000);

    await this.prisma.verificationCode.create({
      data: {
        userId,
        codeHash,
        type,
        expiresAt,
      },
    });

    return code;
  }

  /**
   * Verifica un código OTP.
   * - Si expirado: elimina y lanza error.
   * - Si incorrecto: incrementa attempts; si llega a 3, elimina y lanza error.
   * - Si correcto: elimina el código y retorna true.
   */
  async verify(
    userId: string,
    type: VerificationCodeType,
    code: string,
  ): Promise<{ valid: true }> {
    const record = await this.prisma.verificationCode.findFirst({
      where: { userId, type },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) {
      throw new BadRequestException(
        'No hay código pendiente. Solicite uno nuevo.',
      );
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.verificationCode.delete({ where: { id: record.id } });
      throw new BadRequestException(
        'El código ha expirado. Solicite uno nuevo.',
      );
    }

    const codeHash = this.hashCode(code);
    if (record.codeHash !== codeHash) {
      const newAttempts = record.attempts + 1;
      if (newAttempts >= MAX_ATTEMPTS) {
        await this.prisma.verificationCode.delete({ where: { id: record.id } });
        throw new UnauthorizedException(
          'Demasiados intentos fallidos. Solicite un nuevo código.',
        );
      }
      await this.prisma.verificationCode.update({
        where: { id: record.id },
        data: { attempts: newAttempts },
      });
      throw new UnauthorizedException('Código incorrecto.');
    }

    await this.prisma.verificationCode.delete({ where: { id: record.id } });
    return { valid: true };
  }
}
