import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { JwtAuthGuard, RolesGuard } from './common/guards';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { validateEnv } from './common/config/env.validation';
import { RequestIdMiddleware } from './common/middleware/request-id.middleware';
import { RequestIdInterceptor } from './common/interceptors/request-id.interceptor';
import { ThrottlerStorageModule } from './common/throttler-storage.module';
import { PrismaThrottlerStorage } from './common/storage/prisma-throttler.storage';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: () => validateEnv() as Record<string, unknown>,
    }),
    ScheduleModule.forRoot(),
    PrismaModule,
    ThrottlerStorageModule,
    ThrottlerModule.forRootAsync({
      useFactory: (storage: PrismaThrottlerStorage) => ({
        throttlers: [
          {
            name: 'default',
            ttl: 60000, // 1 minuto
            limit: 100, // 100 peticiones/min por defecto
          },
        ],
        storage,
      }),
      inject: [PrismaThrottlerStorage],
      imports: [ThrottlerStorageModule],
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: RequestIdInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestIdMiddleware).forRoutes('*path');
  }
}
