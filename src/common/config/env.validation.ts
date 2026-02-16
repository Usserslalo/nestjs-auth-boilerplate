import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development')
    .transform((v) => v || 'development'),

  DATABASE_URL: z
    .string()
    .min(1, 'DATABASE_URL es obligatoria')
    .url('DATABASE_URL debe ser una URL válida'),

  JWT_SECRET: z
    .string()
    .min(32, 'JWT_SECRET debe tener al menos 32 caracteres por seguridad'),

  JWT_ACCESS_EXPIRES_IN: z
    .string()
    .optional()
    .transform((v) => (v ? parseInt(v, 10) : 3600)),

  JWT_EXPIRES_IN: z
    .string()
    .optional()
    .transform((v) => (v ? parseInt(v, 10) : undefined)),

  JWT_REFRESH_SECRET: z
    .string()
    .min(32, 'JWT_REFRESH_SECRET debe tener al menos 32 caracteres por seguridad'),

  JWT_REFRESH_EXPIRES_IN: z
    .string()
    .optional()
    .default('604800')
    .transform((v) => (v ? parseInt(v, 10) : 604800)),

  PORT: z
    .string()
    .optional()
    .default('3000')
    .transform((v) => parseInt(v, 10)),

  CORS_ORIGINS: z
    .string()
    .optional()
    .transform((v) =>
      v ? v.split(',').map((o) => o.trim()).filter(Boolean) : [],
    ),

  APP_NAME: z.string().min(1, 'APP_NAME es obligatorio'),

  TWILIO_ACCOUNT_SID: z.string().optional(),

  TWILIO_AUTH_TOKEN: z.string().optional(),

  TWILIO_PHONE_NUMBER: z
    .string()
    .optional()
    .refine((v) => !v || /^\+?[0-9]+$/.test(v), {
      message: 'TWILIO_PHONE_NUMBER debe ser un número con formato E.164 (ej. +16829465567)',
    }),
});

export type Env = z.infer<typeof envSchema>;

export function validateEnv(): Env {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const errors = result.error.flatten();
    const messages = Object.entries(errors.fieldErrors)
      .map(([key, vals]) => `  - ${key}: ${(vals ?? []).join(', ')}`)
      .join('\n');
    throw new Error(
      `❌ Configuración de entorno inválida:\n${messages}\n\nVerifique su archivo .env`,
    );
  }

  return result.data;
}
