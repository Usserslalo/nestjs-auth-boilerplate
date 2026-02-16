/**
 * Abstracción del servicio de mensajería para envío de OTP.
 * Permite implementaciones reales (Twilio) o mock (consola) según configuración.
 */
export type OtpType = 'register' | 'password_reset';

export type MessagingChannel = 'sms' | 'whatsapp';

export interface IMessagingService {
  sendOtp(
    to: string,
    code: string,
    channel?: MessagingChannel,
    type?: OtpType,
  ): Promise<void>;
}

/**
 * Clase base abstracta para inyección en NestJS (token por tipo).
 * Las implementaciones concretas son TwilioMessagingService y MockMessagingService.
 */
export abstract class MessagingService implements IMessagingService {
  abstract sendOtp(
    to: string,
    code: string,
    channel?: MessagingChannel,
    type?: OtpType,
  ): Promise<void>;
}
