import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';
import type { Role } from '@prisma/client';

/**
 * DTO base para respuestas que incluyen datos de usuario.
 * Solo expone campos seguros; password, loginAttempts, tokens, codeHash, etc. nunca viajan al frontend.
 */
@Exclude()
export class UserSafeDto {
  @Expose()
  @ApiProperty({
    format: 'uuid',
    description: 'Identificador único del usuario.',
    example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  })
  id: string;

  @Expose()
  @ApiProperty({
    example: 'usuario@ejemplo.com',
    description: 'Correo electrónico del usuario (único).',
  })
  email: string;

  @Expose()
  @ApiProperty({
    enum: ['ADMIN', 'USER'],
    description: 'Rol del usuario para RBAC.',
  })
  role: Role;

  @Expose()
  @ApiProperty({
    required: false,
    description: 'Si la cuenta fue verificada por OTP.',
  })
  isVerified?: boolean;

  @Expose()
  @ApiProperty({
    example: '+5491112345678',
    required: false,
    description: 'Teléfono en formato E.164 (destino de códigos OTP).',
    nullable: true,
  })
  phoneNumber?: string | null;
}
