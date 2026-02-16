import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';
import type { Role } from '@prisma/client';

/**
 * DTO de usuario para listado y detalle en panel de administración.
 * Expone campos seguros y de auditoría; nunca password ni refreshToken.
 */
@Exclude()
export class UserAdminDto {
  @Expose()
  @ApiProperty({ format: 'uuid', description: 'ID del usuario.' })
  id: string;

  @Expose()
  @ApiProperty({ example: 'usuario@ejemplo.com', description: 'Email único.' })
  email: string;

  @Expose()
  @ApiPropertyOptional({
    example: '+5491112345678',
    description: 'Teléfono E.164.',
    nullable: true,
  })
  phoneNumber?: string | null;

  @Expose()
  @ApiProperty({ enum: ['ADMIN', 'USER'], description: 'Rol del usuario.' })
  role: Role;

  @Expose()
  @ApiProperty({ description: 'Si la cuenta está verificada por OTP.' })
  isVerified: boolean;

  @Expose()
  @ApiProperty({ description: 'Si la cuenta está activa (false = baneada).' })
  isActive: boolean;

  @Expose()
  @ApiProperty({
    description: 'Fecha de creación del usuario.',
    example: '2026-02-16T12:00:00.000Z',
  })
  createdAt: Date;

  @Expose()
  @ApiProperty({
    description: 'Última actualización del registro.',
    example: '2026-02-16T12:00:00.000Z',
  })
  updatedAt: Date;
}
