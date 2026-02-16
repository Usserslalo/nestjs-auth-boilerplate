import 'dotenv/config';
import { NestFactory, Reflector } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ClassSerializerInterceptor, Logger, ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import compression from 'compression';
import { validateEnv, type Env } from './common/config/env.validation';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

const env: Env = validateEnv();
const logger = new Logger('Bootstrap');

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.use(helmet());
  app.use(compression());

  app.useBodyParser('json', { limit: '10kb' });
  app.useBodyParser('urlencoded', { limit: '10kb', extended: true });

  const corsOrigins = env.CORS_ORIGINS ?? [];
  const nodeEnv = env.NODE_ENV ?? 'development';
  const allowedOrigins =
    corsOrigins.length > 0
      ? corsOrigins
      : nodeEnv === 'development'
        ? ['http://localhost:3000', 'http://127.0.0.1:3000']
        : [];

  app.enableCors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : false,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true,
  });

  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(
    new ClassSerializerInterceptor(app.get(Reflector), {
      strategy: 'exposeAll',
    }),
  );

  app.setGlobalPrefix('api');

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Configuración de Swagger
  const config = new DocumentBuilder()
    .setTitle('NestJS Auth Boilerplate API')
    .setDescription(
      'API de autenticación y seguridad: JWT, OTP, RBAC, rate limiting. Rutas públicas: login, register, verify-otp, forgot-password, reset-password, refresh, resend-otp. Resto requiere Bearer Token.',
    )
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
      'access_token',
    )
    .addTag('auth', 'Autenticación y seguridad')
    .addTag('auth-public', 'Rutas públicas (sin JWT)')
    .addTag('auth-protected', 'Rutas protegidas (requieren JWT)')
    .addTag('auth-admin', 'Solo rol ADMIN')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  const port = env.PORT ?? 3000;
  await app.listen(port);
  logger.log(`Servidor corriendo en: http://localhost:${port}/api`);
  logger.log(`Documentación: http://localhost:${port}/docs`);
}
bootstrap();