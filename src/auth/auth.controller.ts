import { Body, Controller, Get, HttpCode, HttpStatus, Patch, Post, Req, UseGuards, UseInterceptors } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { Rfc7807ErrorDto } from '../common/dto/rfc7807-error.dto';
import { CurrentUser, Public, Roles } from '../common/decorators';
import { AuthService, AuthResponse, RegisterResponse } from './auth.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyWhatsAppDto } from './dto/verify-whatsapp.dto';
import { ThrottlerLoggingInterceptor } from './interceptors/throttler-logging.interceptor';
import type { JwtValidatedUser } from '../common/types/auth.types';
import { Role } from '@prisma/client';

/** Límite estricto anti-fuerza bruta: 5 peticiones por minuto en login, verify-otp, reset-password, resend-otp, forgot-password. */
const STRICT_THROTTLE = { default: { limit: 5, ttl: 60000 } };
/** Límite para refresh: 20 rotaciones por minuto para evitar abuso. */
const REFRESH_THROTTLE = { default: { limit: 20, ttl: 60000 } };

@ApiTags('Autenticación', 'auth')
@Controller('auth')
@UseGuards(ThrottlerGuard)
@UseInterceptors(ThrottlerLoggingInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @Public()
  @ApiTags('auth-public')
  @Throttle(STRICT_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Iniciar sesión',
    description:
      'Valida email y contraseña y devuelve access_token (1h) y refresh_token (7d). Devuelve 401 si las credenciales son inválidas, la cuenta no está verificada (use POST /auth/verify-otp) o la cuenta está bloqueada. Rate limit: 5 peticiones/minuto.',
  })
  @ApiOkResponse({
    description: 'Login exitoso. Devuelve access_token, refresh_token y user (id, email, role, phoneNumber).',
    schema: {
      type: 'object',
      properties: {
        access_token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
        refresh_token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string', example: 'carlos.mendoza@gmail.com' },
            role: { type: 'string', enum: ['ADMIN', 'USER'] },
            phoneNumber: { type: 'string', nullable: true },
          },
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (validación DTO).',
    type: Rfc7807ErrorDto,
  })
  @ApiUnauthorizedResponse({
    description:
      'Credenciales inválidas, cuenta no verificada (verifique con POST /auth/verify-otp), cuenta bloqueada por intentos fallidos o temporalmente bloqueada. errorCode: AUTH_UNAUTHORIZED.',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Límite de 5 peticiones por minuto excedido. Incluye header Retry-After.',
    type: Rfc7807ErrorDto,
  })
  async login(
    @Body() dto: LoginDto,
    @Req() req: { ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<AuthResponse> {
    const meta = {
      ip: req.ip ?? req.headers?.['x-forwarded-for'] ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    return this.authService.login(dto, meta);
  }

  @Post('register')
  @Public()
  @ApiTags('auth-public')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Registro de usuario',
    description:
      'Crea un nuevo usuario (rol USER por defecto), envía OTP al teléfono y devuelve tokens. Incluye requiresVerification: true y mensaje para que el frontend muestre la pantalla de verificación (POST /auth/verify-otp). Devuelve 409 si el correo o teléfono ya están registrados.',
  })
  @ApiCreatedResponse({
    description:
      'Registro exitoso. Incluye tokens, user, requiresVerification: true y mensaje indicando verificar con el código enviado al teléfono.',
    schema: {
      type: 'object',
      properties: {
        access_token: { type: 'string' },
        refresh_token: { type: 'string' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string', example: 'usuario@example.com' },
            role: { type: 'string', enum: ['ADMIN', 'USER'] },
            phoneNumber: { type: 'string', nullable: true },
          },
        },
        requiresVerification: { type: 'boolean', example: true },
        message: {
          type: 'string',
          example: 'Usuario registrado con éxito. Por favor, verifica tu cuenta con el código enviado a tu teléfono.',
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (validación DTO).',
    type: Rfc7807ErrorDto,
  })
  @ApiConflictResponse({
    description: 'Ya existe un usuario con este correo electrónico o número de teléfono.',
    type: Rfc7807ErrorDto,
  })
  async register(@Body() dto: RegisterDto): Promise<RegisterResponse> {
    return this.authService.register(dto);
  }

  @Post('verify-otp')
  @Public()
  @ApiTags('auth-public')
  @Throttle(STRICT_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verificar cuenta con código OTP',
    description:
      'Recibe el email y el código OTP de 6 dígitos. Si el código coincide y no ha expirado (10 min), marca isVerified=true. Máx. 3 intentos fallidos. Rate limit: 5 peticiones/minuto.',
  })
  @ApiOkResponse({
    description: 'Cuenta verificada correctamente. El usuario ya puede iniciar sesión.',
    schema: {
      type: 'object',
      properties: { message: { type: 'string', example: 'Cuenta verificada correctamente. Ya puede iniciar sesión.' } },
    },
  })
  @ApiBadRequestResponse({
    description: 'Código expirado o no hay código pendiente de verificación.',
    type: Rfc7807ErrorDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Usuario no encontrado o código incorrecto (máx. 3 intentos).',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Límite de 5 peticiones por minuto excedido.',
    type: Rfc7807ErrorDto,
  })
  async verifyOtp(@Body() dto: VerifyWhatsAppDto): Promise<{ message: string }> {
    return this.authService.verifyOtp(dto);
  }

  @Post('forgot-password')
  @Public()
  @ApiTags('auth-public')
  @Throttle(STRICT_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Solicitar recuperación de contraseña',
    description:
      'Envía un código OTP al teléfono del usuario (si está registrado). Opcional: channel "sms" (por defecto) o "whatsapp". Mensaje genérico para evitar user enumeration. Cooldown 2 min. Rate limit: 5 peticiones/minuto.',
  })
  @ApiOkResponse({
    description: 'Siempre 200 con mensaje genérico (no revela si el email existe).',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Si el correo está registrado, recibirá un código en breve.',
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (validación DTO).',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Too Many Requests (5/min) o cooldown 2 min. Incluye header Retry-After en segundos.',
    type: Rfc7807ErrorDto,
  })
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
    @Req() req: { ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<{ message: string }> {
    const meta = {
      ip: req.ip ?? req.headers?.['x-forwarded-for'] ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    return this.authService.forgotPassword(dto, meta);
  }

  @Post('reset-password')
  @Public()
  @ApiTags('auth-public')
  @Throttle(STRICT_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Restablecer contraseña con código OTP',
    description:
      'Recibe email, código de 6 dígitos y nueva contraseña. Valida OTP (máx. 3 intentos). Rate limit: 5 peticiones/minuto.',
  })
  @ApiOkResponse({
    description: 'Contraseña restablecida correctamente. El usuario ya puede iniciar sesión.',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string', example: 'Contraseña restablecida correctamente. Ya puede iniciar sesión.' },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Código expirado, no hay código pendiente o datos inválidos (ej. contraseña no cumple requisitos).',
    type: Rfc7807ErrorDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Código de restablecimiento incorrecto (máx. 3 intentos).',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Límite de 5 peticiones por minuto excedido.',
    type: Rfc7807ErrorDto,
  })
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<{ message: string }> {
    return this.authService.resetPassword(dto);
  }

  @Post('refresh')
  @Public()
  @ApiTags('auth-public')
  @Throttle(REFRESH_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refrescar tokens (Token Rotation)',
    description:
      'Recibe el refresh_token, lo valida con JWT_REFRESH_SECRET y compara el jti con BD. Emite un nuevo par access_token (1h) y refresh_token (7d). Invalida el refresh anterior. Rate limit: 20 peticiones/minuto. No requiere Bearer Token.',
  })
  @ApiOkResponse({
    description: 'Nuevo par de tokens emitido.',
    schema: {
      type: 'object',
      properties: {
        access_token: { type: 'string' },
        refresh_token: { type: 'string' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string' },
            role: { type: 'string', enum: ['ADMIN', 'USER'] },
            phoneNumber: { type: 'string', nullable: true },
          },
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (validación DTO).',
    type: Rfc7807ErrorDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Refresh token inválido, expirado o ya utilizado.',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Límite de 20 peticiones por minuto excedido.',
    type: Rfc7807ErrorDto,
  })
  async refresh(@Body() dto: RefreshTokenDto): Promise<AuthResponse> {
    return this.authService.refreshTokens(dto.refreshToken);
  }

  @Post('resend-otp')
  @Public()
  @ApiTags('auth-public')
  @Throttle(STRICT_THROTTLE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reenviar código OTP de verificación',
    description:
      'Recibe email y opcionalmente channel ("sms" o "whatsapp"). Genera un nuevo código (cooldown 2 min). Mensaje genérico para evitar user enumeration. Rate limit: 5 peticiones/minuto.',
  })
  @ApiOkResponse({
    description: 'Mensaje genérico (no revela si el email existe o si se reenvió el código).',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Si el correo está registrado y tiene un código pendiente, recibirá uno nuevo en breve.',
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (validación DTO).',
    type: Rfc7807ErrorDto,
  })
  @ApiTooManyRequestsResponse({
    description: 'Too Many Requests o cooldown (2 min entre reenvíos).',
    type: Rfc7807ErrorDto,
  })
  async resendOtp(
    @Body() dto: ResendOtpDto,
    @Req() req: { ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<{ message: string }> {
    const meta = {
      ip: req.ip ?? req.headers?.['x-forwarded-for'] ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    return this.authService.resendOtp(dto, meta);
  }

  @Post('logout')
  @ApiBearerAuth('access_token')
  @ApiTags('auth-protected')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cerrar sesión',
    description:
      'Siempre limpia el jti (refreshToken) del usuario en BD, invalidando el refresh token. Si se envía Authorization: Bearer <token>, además se blacklistea el access token para revocación inmediata. Si no se envía Bearer, solo se invalida el refresh (el access seguirá válido hasta su expiración).',
  })
  @ApiOkResponse({
    description: 'Sesión cerrada correctamente.',
    schema: { type: 'object', properties: { message: { type: 'string', example: 'Sesión cerrada correctamente.' } } },
  })
  @ApiUnauthorizedResponse({
    description: 'Token inválido, expirado o revocado.',
    type: Rfc7807ErrorDto,
  })
  async logout(
    @CurrentUser() user: JwtValidatedUser,
    @Req() req: { headers?: { authorization?: string } },
  ): Promise<{ message: string }> {
    const authHeader = req.headers?.authorization;
    const accessToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : undefined;
    return this.authService.logout(user.userId, accessToken);
  }

  @Patch('change-password')
  @ApiBearerAuth('access_token')
  @ApiTags('auth-protected')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cambiar contraseña',
    description:
      'Valida la contraseña actual antes de permitir el cambio. Requiere Bearer Token. Invalida refresh tokens (debe iniciar sesión de nuevo).',
  })
  @ApiOkResponse({
    description: 'Contraseña actualizada correctamente.',
    schema: {
      type: 'object',
      properties: { message: { type: 'string', example: 'Contraseña actualizada correctamente. Inicie sesión de nuevo.' } },
    },
  })
  @ApiBadRequestResponse({
    description: 'Datos de entrada inválidos (ej. nueva contraseña no cumple requisitos).',
    type: Rfc7807ErrorDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Token inválido, expirado o contraseña actual incorrecta.',
    type: Rfc7807ErrorDto,
  })
  async changePassword(
    @CurrentUser() user: JwtValidatedUser,
    @Body() dto: ChangePasswordDto,
    @Req() req: { ip?: string; headers?: { 'user-agent'?: string } },
  ): Promise<{ message: string }> {
    const meta = {
      ip: req.ip ?? req.headers?.['x-forwarded-for'] ?? 'unknown',
      userAgent: req.headers?.['user-agent'] ?? 'unknown',
    };
    return this.authService.changePassword(user.userId, dto, meta);
  }

  @Get('me')
  @ApiBearerAuth('access_token')
  @ApiTags('auth-protected')
  @ApiOperation({
    summary: 'Perfil del usuario actual',
    description:
      'Devuelve el perfil del usuario autenticado (id, email, role, isVerified, phoneNumber). Requiere Bearer Token. Nunca expone password.',
  })
  @ApiOkResponse({
    description: 'Perfil del usuario actual.',
    type: MeResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Token inválido, expirado o usuario inactivo.',
    type: Rfc7807ErrorDto,
  })
  async getMe(@CurrentUser() user: JwtValidatedUser): Promise<MeResponseDto> {
    const profile = await this.authService.getProfile(user.userId);
    return plainToInstance(MeResponseDto, profile, {
      excludeExtraneousValues: true,
    });
  }

  @Get('admin-only')
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access_token')
  @ApiTags('auth-admin')
  @ApiOperation({
    summary: '[Ejemplo] Solo ADMIN',
    description: 'Ruta de ejemplo que requiere rol ADMIN. Útil para verificar RolesGuard.',
  })
  @ApiOkResponse({
    description: 'Acceso concedido.',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string', example: 'Acceso concedido. Solo usuarios con rol ADMIN pueden ver esto.' },
        userId: { type: 'string', format: 'uuid' },
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Token inválido o expirado.',
    type: Rfc7807ErrorDto,
  })
  @ApiForbiddenResponse({
    description: 'Acceso denegado. Se requiere rol ADMIN.',
    type: Rfc7807ErrorDto,
  })
  adminOnly(@CurrentUser('userId') userId: string): { message: string; userId: string } {
    return {
      message: 'Acceso concedido. Solo usuarios con rol ADMIN pueden ver esto.',
      userId,
    };
  }
}
