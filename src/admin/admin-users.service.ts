import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Role } from '@prisma/client';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ErrorCode } from '../common/constants/error-codes';
import { SecurityLogService } from '../common/services/security-log.service';
import type {
  GetUsersFilterDto,
  SortOrder,
  UserSortField,
} from './dto/get-users-filter.dto';
import { USER_SORT_FIELDS } from './dto/get-users-filter.dto';
import { UserAdminDto } from './dto/user-admin.dto';
import { UpdateUserRoleDto } from './dto/update-user-role.dto';
import { UpdateUserStatusDto } from './dto/update-user-status.dto';

/** Contexto de request para auditoría de acciones administrativas. */
export interface AdminAuditContext {
  requestId: string;
  ip: string;
  userAgent: string;
}

export interface PaginatedUsersResult {
  data: UserAdminDto[];
  meta: {
    total: number;
    page: number;
    limit: number;
    lastPage: number;
  };
}

const USER_SELECT = {
  id: true,
  email: true,
  phoneNumber: true,
  role: true,
  isVerified: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
} as const;

@Injectable()
export class AdminUsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly securityLog: SecurityLogService,
  ) {}

  /**
   * Lista usuarios con paginación, filtros y ordenamiento.
   * Solo debe ser llamado por rutas protegidas con rol ADMIN.
   */
  async findAll(filters: GetUsersFilterDto): Promise<PaginatedUsersResult> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;
    const skip = (page - 1) * limit;
    const sortBy = filters.sortBy ?? 'createdAt';
    const sortOrder = filters.sortOrder ?? 'desc';

    const where = this.buildWhere(filters);
    const orderBy = this.buildOrderBy(sortBy, sortOrder);

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        select: USER_SELECT,
        orderBy,
        skip,
        take: limit,
      }),
      this.prisma.user.count({ where }),
    ]);

    const lastPage = Math.max(1, Math.ceil(total / limit));
    const data = users.map((u) => this.toUserAdminDto(u));

    return {
      data,
      meta: {
        total,
        page,
        limit,
        lastPage,
      },
    };
  }

  /**
   * Activa o desactiva un usuario (banear/reactivar).
   * Impide que un ADMIN se desactive a sí mismo si el contexto lo proporciona.
   * Registra auditoría solo si la actualización en BD fue exitosa.
   */
  async updateStatus(
    userId: string,
    dto: UpdateUserStatusDto,
    currentUserId?: string,
    auditContext?: AdminAuditContext,
  ): Promise<UserAdminDto> {
    if (currentUserId && currentUserId === userId && !dto.isActive) {
      throw new ForbiddenException({
        message: 'No puede desactivar su propia cuenta.',
        errorCode: ErrorCode.AUTH_FORBIDDEN,
      });
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: USER_SELECT,
    });

    if (!user) {
      throw new NotFoundException({
        message: 'Usuario no encontrado.',
        errorCode: ErrorCode.NOT_FOUND,
      });
    }

    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: { isActive: dto.isActive },
      select: USER_SELECT,
    });

    if (currentUserId && auditContext) {
      await this.securityLog.log('ADMIN_USER_STATUS_CHANGE', {
        ip: auditContext.ip,
        userAgent: auditContext.userAgent,
        userId: currentUserId,
        metadata: {
          adminId: currentUserId,
          targetUserId: userId,
          newStatus: dto.isActive,
          requestId: auditContext.requestId,
        },
      });
    }

    return this.toUserAdminDto(updated);
  }

  /**
   * Cambia el rol de un usuario (ADMIN/USER).
   * Puede restringirse que el propio admin no se baje de rol si se pasa currentUserId.
   * Registra auditoría solo si la actualización en BD fue exitosa.
   */
  async updateRole(
    userId: string,
    dto: UpdateUserRoleDto,
    currentUserId?: string,
    auditContext?: AdminAuditContext,
  ): Promise<UserAdminDto> {
    if (currentUserId && currentUserId === userId && dto.role !== Role.ADMIN) {
      throw new ForbiddenException({
        message: 'No puede asignarse a sí mismo un rol distinto de ADMIN.',
        errorCode: ErrorCode.AUTH_FORBIDDEN,
      });
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: USER_SELECT,
    });

    if (!user) {
      throw new NotFoundException({
        message: 'Usuario no encontrado.',
        errorCode: ErrorCode.NOT_FOUND,
      });
    }

    const oldRole = user.role;

    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: { role: dto.role },
      select: USER_SELECT,
    });

    if (currentUserId && auditContext) {
      await this.securityLog.log('ADMIN_USER_ROLE_CHANGE', {
        ip: auditContext.ip,
        userAgent: auditContext.userAgent,
        userId: currentUserId,
        metadata: {
          adminId: currentUserId,
          targetUserId: userId,
          oldRole,
          newRole: dto.role,
          requestId: auditContext.requestId,
        },
      });
    }

    return this.toUserAdminDto(updated);
  }

  private buildWhere(filters: GetUsersFilterDto): Prisma.UserWhereInput {
    const conditions: Prisma.UserWhereInput[] = [];

    if (filters.role !== undefined) {
      conditions.push({ role: filters.role });
    }
    if (filters.isActive !== undefined) {
      conditions.push({ isActive: filters.isActive });
    }
    if (filters.isVerified !== undefined) {
      conditions.push({ isVerified: filters.isVerified });
    }
    if (filters.search?.trim()) {
      const term = filters.search.trim();
      conditions.push({
        OR: [
          { email: { contains: term, mode: 'insensitive' } },
          { phoneNumber: { contains: term, mode: 'insensitive' } },
        ],
      });
    }

    return conditions.length > 0 ? { AND: conditions } : {};
  }

  private buildOrderBy(
    sortBy: UserSortField,
    sortOrder: SortOrder,
  ): Prisma.UserOrderByWithRelationInput {
    const order = sortOrder === 'desc' ? 'desc' : 'asc';
    if (!USER_SORT_FIELDS.includes(sortBy)) {
      return { createdAt: 'desc' };
    }
    return { [sortBy]: order };
  }

  private toUserAdminDto(row: {
    id: string;
    email: string;
    phoneNumber: string | null;
    role: Role;
    isVerified: boolean;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
  }): UserAdminDto {
    return {
      id: row.id,
      email: row.email,
      phoneNumber: row.phoneNumber ?? null,
      role: row.role,
      isVerified: row.isVerified,
      isActive: row.isActive,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }
}
