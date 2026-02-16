import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { SecurityLogService } from '../common/services/security-log.service';
import { AdminUsersService } from './admin-users.service';
import { UsersController } from './users.controller';

@Module({
  imports: [PrismaModule],
  controllers: [UsersController],
  providers: [AdminUsersService, SecurityLogService],
  exports: [AdminUsersService],
})
export class AdminModule {}
