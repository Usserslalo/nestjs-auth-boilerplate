import { ApiProperty } from '@nestjs/swagger';

/**
 * Respuesta de error estándar (RFC 7807 style).
 * Todas las respuestas 4xx y 5xx devuelven este esquema.
 */
export class Rfc7807ErrorDto {
  @ApiProperty({
    example: false,
    description: 'Indica que la petición no fue exitosa.',
  })
  success: false;

  @ApiProperty({
    example: 400,
    description: 'Código HTTP de estado.',
    enum: [400, 401, 403, 404, 409, 422, 429, 500],
  })
  statusCode: number;

  @ApiProperty({
    example: 'BAD_REQUEST',
    description: 'Código de error interno para el cliente (slug en mayúsculas).',
    examples: [
      'BAD_REQUEST',
      'AUTH_UNAUTHORIZED',
      'FORBIDDEN',
      'NOT_FOUND',
      'CONFLICT',
      'RATE_LIMIT_EXCEEDED',
      'INTERNAL_SERVER_ERROR',
    ],
  })
  errorCode: string;

  @ApiProperty({
    example: 'El email debe ser un correo válido',
    description: 'Mensaje legible para el usuario.',
  })
  message: string;

  @ApiProperty({
    example: '/api/auth/login',
    description: 'Ruta de la petición que generó el error.',
  })
  path: string;

  @ApiProperty({
    example: '2026-02-16T12:00:00.000Z',
    description: 'Fecha y hora del error en ISO 8601.',
  })
  timestamp: string;

  @ApiProperty({
    example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    description: 'ID único de la petición (también en header X-Request-ID).',
  })
  requestId: string;

  @ApiProperty({
    type: [String],
    required: false,
    description: 'Lista de mensajes por campo (solo en errores de validación DTO).',
    example: ['email must be an email', 'password must be longer than or equal to 6 characters'],
  })
  errors?: string[];
}
