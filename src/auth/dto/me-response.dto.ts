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
  @ApiProperty({ format: 'uuid', description: 'ID del usuario' })
  id: string;

  @Expose()
  @ApiProperty({ example: 'usuario@ejemplo.com', description: 'Email del usuario' })
  email: string;

  @Expose()
  @ApiProperty({ enum: ['ADMIN', 'USER'], description: 'Rol del usuario' })
  role: Role;

  @Expose()
  @ApiProperty({
    description: 'Si la cuenta fue verificada por OTP',
    example: true,
  })
  isVerified: boolean;

  @Expose()
  @ApiProperty({
    description: 'Número de teléfono E.164 (destino de los códigos OTP)',
    example: '+5491112345678',
    required: false,
  })
  phoneNumber?: string | null;
}
