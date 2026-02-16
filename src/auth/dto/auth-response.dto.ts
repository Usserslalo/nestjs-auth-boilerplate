import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose, Type } from 'class-transformer';
import { UserSafeDto } from '../../common/dto/user-safe.dto';

/**
 * Respuesta de login, register y refresh.
 * Serialización segura vía ClassSerializerInterceptor.
 */
@Exclude()
export class AuthResponseDto {
  @Expose()
  @ApiProperty({
    description: 'JWT de acceso. Incluir en cabecera Authorization: Bearer <token>. Expira en 1h por defecto.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  access_token: string;

  @Expose()
  @ApiProperty({
    description: 'JWT de refresco. Usar en POST /auth/refresh para obtener un nuevo par. Expira en 7d por defecto.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refresh_token: string;

  @Expose()
  @ApiProperty({ type: UserSafeDto })
  @Type(() => UserSafeDto)
  user: UserSafeDto;
}
