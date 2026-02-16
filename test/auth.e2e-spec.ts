import { INestApplication } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import { ValidationPipe, ClassSerializerInterceptor } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AppModule } from '../src/app.module';
import { HttpExceptionFilter } from '../src/common/filters/http-exception.filter';

/**
 * E2E: Login fallido repetido -> bloqueo de cuenta.
 * Requiere BD con usuario admin@example.com (seed) y migraciones aplicadas.
 */
describe('AuthController (e2e) - Bloqueo por intentos fallidos', () => {
  let app: INestApplication;
  const TEST_EMAIL = 'admin@example.com';
  const WRONG_PASSWORD = 'WrongPassword123!';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalFilters(new HttpExceptionFilter());
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
    );
    app.useGlobalInterceptors(
      new ClassSerializerInterceptor(app.get(Reflector), { strategy: 'exposeAll' }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('5 intentos fallidos -> 6º intento devuelve 401 (cuenta bloqueada)', async () => {
    for (let i = 0; i < 5; i++) {
      const res = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: WRONG_PASSWORD })
        .expect(401);
      expect(res.body.success).toBe(false);
    }

    const resLocked = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: WRONG_PASSWORD })
      .expect(401);

    expect(resLocked.body.success).toBe(false);
    expect(resLocked.body.errorCode).toBeDefined();
  });
});
