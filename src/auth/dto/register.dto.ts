import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, Matches, MinLength } from 'class-validator';

/** Formato E.164: + seguido de 1-15 dígitos (sin espacios ni guiones). */
const E164_REGEX = /^\+[1-9]\d{1,14}$/;

export class RegisterDto {
  @ApiProperty({
    example: 'usuario@ejemplo.com',
    description: 'Correo electrónico (único en el sistema)',
  })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsString()
  @IsEmail({}, { message: 'El email debe ser un correo válido' })
  @IsNotEmpty({ message: 'El email es obligatorio' })
  email: string;

  @ApiProperty({
    example: '+527711440305',
    description: 'Teléfono en formato E.164 (+ seguido de 1-15 dígitos). Se usa para enviar el OTP por SMS o WhatsApp según channel.',
    pattern: '^\\+[1-9]\\d{1,14}$',
  })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @IsString()
  @IsNotEmpty({ message: 'El número de teléfono es obligatorio' })
  @Matches(E164_REGEX, {
    message: 'El teléfono debe estar en formato E.164 (ej: +527711440305)',
  })
  phoneNumber: string;

  @ApiPropertyOptional({
    enum: ['sms', 'whatsapp'],
    default: 'sms',
    description: 'Canal para recibir el código OTP: "sms" o "whatsapp" (por defecto: sms)',
  })
  @IsOptional()
  @IsString()
  @IsIn(['sms', 'whatsapp'], { message: 'channel debe ser "sms" o "whatsapp"' })
  channel?: 'sms' | 'whatsapp';

  @ApiProperty({
    example: 'MiClave#123',
    description: 'Contraseña (mínimo 6 caracteres, al menos una letra y un número)',
    minLength: 6,
  })
  @IsString()
  @IsNotEmpty({ message: 'La contraseña es obligatoria' })
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  @Matches(/^(?=.*[a-zA-Z])(?=.*\d)/, {
    message: 'La contraseña debe contener al menos una letra y un número',
  })
  password: string;
}
