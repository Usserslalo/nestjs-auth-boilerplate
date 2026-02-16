import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import {
  ApiBearerAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Role } from '@prisma/client';
import { Rfc7807ErrorDto } from '../common/dto/rfc7807-error.dto';
import { CurrentUser, Roles } from '../common/decorators';
import type { JwtValidatedUser } from '../common/types/auth.types';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import {
  AdminUsersService,
  AdminAuditContext,
  PaginatedUsersResult,
} from './admin-users.service';
import { GetUsersFilterDto } from './dto/get-users-filter.dto';
import { UserAdminDto } from './dto/user-admin.dto';
import { UpdateUserRoleDto } from './dto/update-user-role.dto';
import { UpdateUserStatusDto } from './dto/update-user-status.dto';

@ApiTags('Admin', 'auth-admin')
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth('access_token')
@UseGuards(ThrottlerGuard)
export class UsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Get('users')
  @ApiOperation({
    summary: 'Listar usuarios (paginado)',
    description:
      'Lista todos los usuarios con paginación, filtros (role, isActive, isVerified), búsqueda parcial por email/teléfono y ordenamiento. Solo disponible para rol ADMIN.',
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Página (1-based). Default: 1.' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Registros por página (1-100). Default: 10.' })
  @ApiQuery({ name: 'role', required: false, enum: Role, description: 'Filtrar por rol.' })
  @ApiQuery({ name: 'isActive', required: false, type: Boolean, description: 'Filtrar por cuenta activa.' })
  @ApiQuery({ name: 'isVerified', required: false, type: Boolean, description: 'Filtrar por cuenta verificada.' })
  @ApiQuery({ name: 'search', required: false, type: String, description: 'Búsqueda parcial en email o phoneNumber.' })
  @ApiQuery({ name: 'sortBy', required: false, enum: ['email', 'createdAt', 'updatedAt', 'role'], description: 'Campo de orden. Default: createdAt.' })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'], description: 'Orden. Default: desc.' })
  @ApiOkResponse({
    description: 'Lista paginada de usuarios.',
    schema: {
      type: 'object',
      properties: {
        data: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              email: { type: 'string' },
              phoneNumber: { type: 'string', nullable: true },
              role: { type: 'string', enum: ['ADMIN', 'USER'] },
              isVerified: { type: 'boolean' },
              isActive: { type: 'boolean' },
              createdAt: { type: 'string', format: 'date-time' },
              updatedAt: { type: 'string', format: 'date-time' },
            },
          },
        },
        meta: {
          type: 'object',
          properties: {
            total: { type: 'number', example: 42 },
            page: { type: 'number', example: 1 },
            limit: { type: 'number', example: 10 },
            lastPage: { type: 'number', example: 5 },
          },
        },
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'No autenticado o token inválido/expirado.',
    type: Rfc7807ErrorDto,
  })
  @ApiForbiddenResponse({
    description: 'Acceso denegado. Se requiere rol ADMIN.',
    type: Rfc7807ErrorDto,
  })
  async getUsers(
    @Query() filters: GetUsersFilterDto,
  ): Promise<PaginatedUsersResult> {
    return this.adminUsersService.findAll(filters);
  }

  @Patch('users/:id/status')
  @ApiOperation({
    summary: 'Activar o desactivar usuario',
    description:
      'Permite activar (isActive: true) o desactivar/banear (isActive: false) un usuario. Un admin no puede desactivar su propia cuenta.',
  })
  @ApiOkResponse({
    description: 'Usuario actualizado.',
    type: UserAdminDto,
  })
  @ApiUnauthorizedResponse({
    description: 'No autenticado o token inválido.',
    type: Rfc7807ErrorDto,
  })
  @ApiForbiddenResponse({
    description: 'No es ADMIN o intenta desactivar su propia cuenta.',
    type: Rfc7807ErrorDto,
  })
  @ApiNotFoundResponse({
    description: 'Usuario no encontrado.',
    type: Rfc7807ErrorDto,
  })
  async updateUserStatus(
    @Param('id') id: string,
    @Body() dto: UpdateUserStatusDto,
    @CurrentUser() currentUser: JwtValidatedUser,
    @Req() req: { requestId?: string; ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<UserAdminDto> {
    const auditContext: AdminAuditContext = {
      requestId: req.requestId ?? 'unknown',
      ip: req.ip ?? (req.headers?.['x-forwarded-for'] as string) ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    const user = await this.adminUsersService.updateStatus(
      id,
      dto,
      currentUser.userId,
      auditContext,
    );
    return plainToInstance(UserAdminDto, user, {
      excludeExtraneousValues: true,
    });
  }

  @Patch('users/:id/role')
  @ApiOperation({
    summary: 'Cambiar rol de usuario',
    description:
      'Asigna un nuevo rol (ADMIN o USER) al usuario. Un admin no puede asignarse a sí mismo un rol distinto de ADMIN.',
  })
  @ApiOkResponse({
    description: 'Usuario actualizado.',
    type: UserAdminDto,
  })
  @ApiUnauthorizedResponse({
    description: 'No autenticado o token inválido.',
    type: Rfc7807ErrorDto,
  })
  @ApiForbiddenResponse({
    description: 'No es ADMIN o intenta cambiarse su propio rol a no-ADMIN.',
    type: Rfc7807ErrorDto,
  })
  @ApiNotFoundResponse({
    description: 'Usuario no encontrado.',
    type: Rfc7807ErrorDto,
  })
  async updateUserRole(
    @Param('id') id: string,
    @Body() dto: UpdateUserRoleDto,
    @CurrentUser() currentUser: JwtValidatedUser,
    @Req() req: { requestId?: string; ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<UserAdminDto> {
    const auditContext: AdminAuditContext = {
      requestId: req.requestId ?? 'unknown',
      ip: req.ip ?? (req.headers?.['x-forwarded-for'] as string) ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    const user = await this.adminUsersService.updateRole(
      id,
      dto,
      currentUser.userId,
      auditContext,
    );
    return plainToInstance(UserAdminDto, user, {
      excludeExtraneousValues: true,
    });
  }
}
