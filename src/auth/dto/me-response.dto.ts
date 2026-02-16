import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';
import type { Role } from '@prisma/client';

/**
 * Respuesta del endpoint GET /auth/me.
 * Solo expone campos seguros (ClassSerializerInterceptor).
 */
@Exclude()
export class MeResponseDto {
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
    description: 'Correo electrónico del usuario.',
  })
  email: string;

  @Expose()
  @ApiProperty({
    enum: ['ADMIN', 'USER'],
    description: 'Rol del usuario (RBAC).',
  })
  role: Role;

  @Expose()
  @ApiProperty({
    description: 'Si la cuenta fue verificada por código OTP.',
    example: true,
  })
  isVerified: boolean;

  @Expose()
  @ApiProperty({
    description: 'Número de teléfono E.164 (destino de los códigos OTP).',
    example: '+5491112345678',
    required: false,
    nullable: true,
  })
  phoneNumber?: string | null;
}
