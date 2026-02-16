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
  @ApiProperty({ format: 'uuid' })
  id: string;

  @Expose()
  @ApiProperty({ example: 'usuario@ejemplo.com' })
  email: string;

  @Expose()
  @ApiProperty({ enum: ['ADMIN', 'USER'] })
  role: Role;

  @Expose()
  @ApiProperty({ required: false })
  isVerified?: boolean;

  @Expose()
  @ApiProperty({ example: '+5491112345678', required: false })
  phoneNumber?: string | null;
}
