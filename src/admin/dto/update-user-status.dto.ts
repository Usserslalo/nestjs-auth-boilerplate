import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean } from 'class-validator';

export class UpdateUserStatusDto {
  @ApiProperty({
    description: 'true para activar la cuenta, false para desactivar (banear).',
    example: false,
  })
  @IsBoolean()
  isActive: boolean;
}
