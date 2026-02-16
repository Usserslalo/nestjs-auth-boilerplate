import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Role, VerificationCodeType } from '@prisma/client';
import * as argon2 from 'argon2';
import { randomUUID } from 'crypto';
import { BlacklistService } from '../common/services/blacklist.service';
import { SecurityLogService } from '../common/services/security-log.service';
import { PrismaService } from '../prisma/prisma.service';
import { MessagingService } from './messaging.service';
import { OtpService } from './otp.service';
import { ROLES } from './constants/roles';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyWhatsAppDto } from './dto/verify-whatsapp.dto';

/** Parámetros Argon2 recomendados: argon2id, 64 MiB memoria, 2 iteraciones. */
const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 2,
};
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 15;
const ACCESS_TOKEN_EXPIRES_SEC = 3600; // 1h
const REFRESH_TOKEN_EXPIRES_SEC = 604800; // 7d

/** Mensaje genérico para evitar user enumeration en recuperación de contraseña. */
const FORGOT_PASSWORD_RESPONSE_MESSAGE =
  'Si el correo está registrado, recibirá un código en breve.';

/** Mensaje genérico para resend OTP (evitar user enumeration). */
const RESEND_OTP_RESPONSE_MESSAGE =
  'Si el correo está registrado y tiene un código pendiente, recibirá uno nuevo en breve.';

/** Mensaje genérico en login para evitar user enumeration (usuario no existe, contraseña incorrecta o cuenta bloqueada). */
const LOGIN_INVALID_CREDENTIALS_MESSAGE =
  'Credenciales inválidas o cuenta temporalmente bloqueada.';

export interface JwtPayload {
  sub: string;
  email: string;
  role: Role;
}

export interface RefreshTokenPayload extends JwtPayload {
  jti: string;
}

export interface RequestMeta {
  ip: string;
  userAgent: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    email: string;
    role: Role;
    phoneNumber?: string | null;
  };
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly blacklistService: BlacklistService,
    private readonly otpService: OtpService,
    private readonly messagingService: MessagingService,
    private readonly securityLog: SecurityLogService,
  ) {}

  async login(dto: LoginDto, meta?: RequestMeta): Promise<AuthResponse> {
    const ip = meta?.ip ?? 'unknown';
    const userAgent = meta?.userAgent ?? 'unknown';

    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: {
        id: true,
        email: true,
        role: true,
        phoneNumber: true,
        password: true,
        isActive: true,
        isVerified: true,
        loginAttempts: true,
        lockUntil: true,
      },
    });

    if (!user) {
      await this.securityLog.log('LOGIN_FAILED', { ip, userAgent });
      throw new UnauthorizedException(LOGIN_INVALID_CREDENTIALS_MESSAGE);
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      await this.securityLog.log('ACCOUNT_LOCKED', {
        ip,
        userAgent,
        userId: user.id,
      });
      throw new UnauthorizedException(LOGIN_INVALID_CREDENTIALS_MESSAGE);
    }

    if (!user.isActive || !user.isVerified) {
      await this.securityLog.log('LOGIN_FAILED', {
        ip,
        userAgent,
        userId: user.id,
      });
      throw new UnauthorizedException(LOGIN_INVALID_CREDENTIALS_MESSAGE);
    }

    const isPasswordValid = await argon2.verify(user.password, dto.password);
    if (!isPasswordValid) {
      const newAttempts = user.loginAttempts + 1;
      const lockUntil =
        newAttempts >= MAX_LOGIN_ATTEMPTS
          ? new Date(Date.now() + LOCK_DURATION_MINUTES * 60 * 1000)
          : null;

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: newAttempts,
          lockUntil,
        },
      });

      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        await this.securityLog.log('ACCOUNT_LOCKED', {
          ip,
          userAgent,
          userId: user.id,
        });
      } else {
        await this.securityLog.log('LOGIN_FAILED', {
          ip,
          userAgent,
          userId: user.id,
        });
      }

      throw new UnauthorizedException(LOGIN_INVALID_CREDENTIALS_MESSAGE);
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { loginAttempts: 0, lockUntil: null },
    });

    await this.securityLog.log('LOGIN_SUCCESS', {
      ip,
      userAgent,
      userId: user.id,
    });

    const tokens = await this.issueTokenPair(user.id, user.email, user.role);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        phoneNumber: user.phoneNumber ?? null,
      },
    };
  }

  /**
   * Emite access_token (1h) y refresh_token (7d con jti); persiste jti en User para rotación.
   */
  private async issueTokenPair(
    userId: string,
    email: string,
    role: Role,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const payload: JwtPayload = { sub: userId, email, role };
    const jti = randomUUID();
    const refreshPayload: RefreshTokenPayload = { ...payload, jti };

    const access_token = this.jwtService.sign(payload, {
      expiresIn: ACCESS_TOKEN_EXPIRES_SEC,
    });
    const refresh_token = this.jwtService.sign(refreshPayload, {
      expiresIn: REFRESH_TOKEN_EXPIRES_SEC,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: jti },
    });

    return { access_token, refresh_token };
  }

  /**
   * Refresh tokens (Token Rotation): valida refresh_token, compara jti con BD, emite nuevo par.
   */
  async refreshTokens(refreshToken: string): Promise<AuthResponse> {
    let payload: RefreshTokenPayload;
    try {
      payload = this.jwtService.verify<RefreshTokenPayload>(refreshToken);
    } catch {
      throw new UnauthorizedException('Refresh token inválido o expirado');
    }

    const { sub, jti } = payload;
    const user = await this.prisma.user.findUnique({
      where: { id: sub },
      select: {
        id: true,
        email: true,
        role: true,
        phoneNumber: true,
        refreshToken: true,
        isActive: true,
      },
    });

    if (!user || !user.isActive || user.refreshToken !== jti) {
      throw new UnauthorizedException('Refresh token inválido o ya utilizado');
    }

    const tokens = await this.issueTokenPair(user.id, user.email, user.role);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        phoneNumber: user.phoneNumber ?? null,
      },
    };
  }

  /**
   * Logout: limpia refreshToken del usuario, añade el access token a la blacklist
   * (invalida sesión para rotación y bloquea el token hasta su expiración).
   */
  async logout(userId: string, accessToken?: string): Promise<{ message: string }> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    if (accessToken) {
      const decoded = this.jwtService.decode(accessToken) as { exp?: number } | null;
      const expiresAt = decoded?.exp
        ? new Date(decoded.exp * 1000)
        : new Date(Date.now() + ACCESS_TOKEN_EXPIRES_SEC * 1000);
      await this.blacklistService.add(accessToken, expiresAt);
    }

    return { message: 'Sesión cerrada correctamente.' };
  }

  /**
   * Cambio de contraseña (protegido por JWT). Valida contraseña actual; invalida refresh tokens.
   */
  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    meta?: RequestMeta,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true },
    });

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    const isCurrentValid = await argon2.verify(user.password, dto.currentPassword);
    if (!isCurrentValid) {
      throw new UnauthorizedException('Contraseña actual incorrecta');
    }

    const hashedPassword = await argon2.hash(dto.newPassword, ARGON2_OPTIONS);

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword, refreshToken: null },
    });

    await this.securityLog.log('PASSWORD_CHANGED', {
      ip: meta?.ip ?? 'unknown',
      userAgent: meta?.userAgent ?? 'unknown',
      userId,
    });

    return { message: 'Contraseña actualizada correctamente. Inicie sesión de nuevo.' };
  }

  /**
   * Reenvío de OTP de verificación. Cooldown 2 min. Mensaje genérico para evitar user enumeration.
   * Solo envía si el usuario tiene phoneNumber registrado. Canal opcional: sms (por defecto) o whatsapp.
   */
  async resendOtp(
    dto: ResendOtpDto,
    meta?: RequestMeta,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, phoneNumber: true },
    });

    if (!user) {
      return { message: RESEND_OTP_RESPONSE_MESSAGE };
    }

    const channel = dto.channel ?? 'sms';

    if (user.phoneNumber) {
      const code = await this.otpService.create(user.id, VerificationCodeType.REGISTER);
await this.messagingService.sendOtp(user.phoneNumber, code, channel, 'register');
    await this.securityLog.log('OTP_SENT', {
      ip: meta?.ip ?? 'unknown',
      userAgent: meta?.userAgent ?? 'unknown',
      userId: user.id,
      channel: channel === 'sms' ? 'SMS' : 'WHATSAPP',
    });
  }

  return { message: RESEND_OTP_RESPONSE_MESSAGE };
}

  /**
   * Registro: crea un User con email, phoneNumber y contraseña (rol USER por defecto) y envía OTP al teléfono.
   */
  async register(dto: RegisterDto): Promise<AuthResponse> {
    const existingByEmail = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (existingByEmail) {
      throw new ConflictException(
        'Ya existe un usuario registrado con este correo electrónico',
      );
    }

    const existingByPhone = await this.prisma.user.findUnique({
      where: { phoneNumber: dto.phoneNumber },
    });
    if (existingByPhone) {
      throw new ConflictException(
        'Ya existe un usuario registrado con este número de teléfono',
      );
    }

    const hashedPassword = await argon2.hash(dto.password, ARGON2_OPTIONS);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        phoneNumber: dto.phoneNumber,
        password: hashedPassword,
        role: ROLES.USER,
        isVerified: false,
      },
      select: {
        id: true,
        email: true,
        role: true,
        phoneNumber: true,
      },
    });

    const channel = dto.channel ?? 'sms';

    const code = await this.otpService.create(user.id, VerificationCodeType.REGISTER);
    await this.messagingService.sendOtp(user.phoneNumber!, code, channel, 'register');
    await this.securityLog.log('OTP_SENT', {
      ip: 'unknown',
      userAgent: 'unknown',
      userId: user.id,
      channel: channel === 'sms' ? 'SMS' : 'WHATSAPP',
    });

    const tokens = await this.issueTokenPair(user.id, user.email, user.role);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        phoneNumber: user.phoneNumber ?? null,
      },
    };
  }

  /**
   * Solicitud de recuperación de contraseña.
   * Genera OTP con cooldown 2 min. Solo envía si el usuario tiene phoneNumber.
   * Canal opcional: sms (por defecto) o whatsapp. Mensaje genérico para evitar user enumeration.
   */
  async forgotPassword(
    dto: ForgotPasswordDto,
    meta?: RequestMeta,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, phoneNumber: true },
    });

    if (!user) {
      return { message: FORGOT_PASSWORD_RESPONSE_MESSAGE };
    }

    const channel = dto.channel ?? 'sms';

    if (user.phoneNumber) {
      const code = await this.otpService.create(
        user.id,
        VerificationCodeType.PASSWORD_RESET,
      );
      await this.messagingService.sendOtp(user.phoneNumber, code, channel, 'password_reset');
      await this.securityLog.log('OTP_SENT', {
        ip: meta?.ip ?? 'unknown',
        userAgent: meta?.userAgent ?? 'unknown',
        userId: user.id,
        channel: channel === 'sms' ? 'SMS' : 'WHATSAPP',
      });
    }

    return { message: FORGOT_PASSWORD_RESPONSE_MESSAGE };
  }

  /**
   * Restablece la contraseña con el código OTP. Valida OTP vía OtpService.
   */
  async resetPassword(dto: ResetPasswordDto): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new BadRequestException('Código inválido o expirado. Solicite uno nuevo.');
    }

    await this.otpService.verify(
      user.id,
      VerificationCodeType.PASSWORD_RESET,
      dto.code,
    );

    const hashedPassword = await argon2.hash(dto.newPassword, ARGON2_OPTIONS);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });

    return { message: 'Contraseña restablecida correctamente. Ya puede iniciar sesión.' };
  }

  /**
   * Verifica el código OTP y marca la cuenta como verificada.
   */
  async verifyOtp(dto: VerifyWhatsAppDto): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    await this.otpService.verify(user.id, VerificationCodeType.REGISTER, dto.code);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });

    return { message: 'Cuenta verificada correctamente. Ya puede iniciar sesión.' };
  }

  /**
   * Valida que el usuario exista, esté activo y verificado (útil para JwtStrategy).
   */
  async validateUserById(userId: string) {
    return this.prisma.user.findFirst({
      where: {
        id: userId,
        isActive: true,
        isVerified: true,
      },
      select: {
        id: true,
        email: true,
        role: true,
      },
    });
  }

  /**
   * Obtiene el perfil del usuario autenticado (id, email, role, isVerified, phoneNumber). Nunca devuelve password.
   */
  async getProfile(userId: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        role: true,
        isVerified: true,
        phoneNumber: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado o inactivo');
    }

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
      phoneNumber: user.phoneNumber ?? null,
    };
  }
}
