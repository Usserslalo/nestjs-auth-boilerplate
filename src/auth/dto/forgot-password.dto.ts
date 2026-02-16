import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'usuario@ejemplo.com',
    description: 'Correo electrónico de la cuenta a recuperar',
  })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsString()
  @IsEmail({}, { message: 'El email debe ser un correo válido' })
  @IsNotEmpty({ message: 'El email es obligatorio' })
  email: string;

  @ApiPropertyOptional({
    enum: ['sms', 'whatsapp'],
    default: 'sms',
    description: 'Canal por el que recibir el código OTP (SMS o WhatsApp Sandbox)',
  })
  @IsOptional()
  @IsString()
  @IsIn(['sms', 'whatsapp'], { message: 'channel debe ser "sms" o "whatsapp"' })
  channel?: 'sms' | 'whatsapp';
}
