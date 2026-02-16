import { Global, Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { PrismaThrottlerStorage } from './storage/prisma-throttler.storage';

@Global()
@Module({
  imports: [PrismaModule],
  providers: [PrismaThrottlerStorage],
  exports: [PrismaThrottlerStorage],
})
export class ThrottlerStorageModule {}
