import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { Role } from '@prisma/client';

const toBoolean = (v: unknown): boolean =>
  v === true || v === 'true' || v === 1 || v === '1';

/** Campos por los que se puede ordenar la lista de usuarios. */
export const USER_SORT_FIELDS = ['email', 'createdAt', 'updatedAt', 'role'] as const;
export type UserSortField = (typeof USER_SORT_FIELDS)[number];

export const SORT_ORDER = ['asc', 'desc'] as const;
export type SortOrder = (typeof SORT_ORDER)[number];

export class GetUsersFilterDto {
  @ApiPropertyOptional({
    description: 'Página actual (1-based).',
    default: 1,
    minimum: 1,
    example: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Cantidad de registros por página.',
    default: 10,
    minimum: 1,
    maximum: 100,
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 10;

  @ApiPropertyOptional({
    enum: Role,
    description: 'Filtrar por rol (ADMIN o USER).',
  })
  @IsOptional()
  @IsEnum(Role)
  role?: Role;

  @ApiPropertyOptional({
    description: 'Filtrar por cuenta activa (true) o inactiva/baneada (false).',
    example: true,
  })
  @IsOptional()
  @Transform(({ value }) => (value === undefined ? undefined : toBoolean(value)))
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'Filtrar por cuenta verificada por OTP (true) o no verificada (false).',
    example: true,
  })
  @IsOptional()
  @Transform(({ value }) => (value === undefined ? undefined : toBoolean(value)))
  @IsBoolean()
  isVerified?: boolean;

  @ApiPropertyOptional({
    description: 'Búsqueda parcial por email o phoneNumber (case-insensitive). Se aplica trim automático.',
    example: 'juan',
  })
  @IsOptional()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @IsString()
  search?: string;

  @ApiPropertyOptional({
    enum: USER_SORT_FIELDS,
    description: 'Campo por el que ordenar.',
    default: 'createdAt',
  })
  @IsOptional()
  @IsEnum(USER_SORT_FIELDS)
  sortBy?: UserSortField = 'createdAt';

  @ApiPropertyOptional({
    enum: SORT_ORDER,
    description: 'Dirección del orden (asc o desc).',
    default: 'desc',
  })
  @IsOptional()
  @IsEnum(SORT_ORDER)
  sortOrder?: SortOrder = 'desc';
}
