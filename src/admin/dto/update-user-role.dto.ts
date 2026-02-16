import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { Role } from '@prisma/client';

export class UpdateUserRoleDto {
  @ApiProperty({
    enum: Role,
    description: 'Nuevo rol del usuario (ADMIN o USER).',
    example: 'USER',
  })
  @IsEnum(Role)
  role: Role;
}
