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
  @ApiProperty()
  access_token: string;

  @Expose()
  @ApiProperty()
  refresh_token: string;

  @Expose()
  @ApiProperty({ type: UserSafeDto })
  @Type(() => UserSafeDto)
  user: UserSafeDto;
}
