import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Twilio from 'twilio';

export type OtpType = 'register' | 'password_reset';

export type MessagingChannel = 'sms' | 'whatsapp';

const OTP_MESSAGES: Record<OtpType, string> = {
  register:
    'Este es tu código para verificar tu cuenta en {{appName}}: {{code}}. Expira en 10 minutos.',
  password_reset:
    'Este es tu código para restablecer tu contraseña en {{appName}}: {{code}}. Expira en 10 minutos.',
};

/** Número del Sandbox de WhatsApp de Twilio (join code en el chat para activar). */
const TWILIO_WHATSAPP_SANDBOX_NUMBER = '+14155238886';

/**
 * Servicio de mensajería para envío de códigos OTP vía Twilio (SMS o WhatsApp).
 * SMS: from = TWILIO_PHONE_NUMBER (+16829465567). WhatsApp: from = whatsapp:+14155238886.
 */
@Injectable()
export class MessagingService {
  private readonly logger = new Logger(MessagingService.name);
  private readonly twilioClient: Twilio.Twilio;
  private readonly twilioPhoneSms: string;
  private readonly appName: string;

  constructor(private readonly config: ConfigService) {
    const accountSid = this.config.getOrThrow<string>('TWILIO_ACCOUNT_SID');
    const authToken = this.config.getOrThrow<string>('TWILIO_AUTH_TOKEN');
    this.twilioPhoneSms = this.config.getOrThrow<string>('TWILIO_PHONE_NUMBER');
    this.appName = this.config.getOrThrow<string>('APP_NAME');
    this.twilioClient = Twilio(accountSid, authToken);
  }

  /**
   * Envía un código OTP al destinatario por el canal indicado.
   * El texto del mensaje depende del tipo: verificación de cuenta o restablecimiento de contraseña.
   * - sms: from = TWILIO_PHONE_NUMBER, to = número E.164.
   * - whatsapp: from = whatsapp:+14155238886, to = whatsapp:+número E.164.
   */
  async sendOtp(
    to: string,
    code: string,
    channel: MessagingChannel = 'sms',
    type: OtpType = 'register',
  ): Promise<void> {
    const template = OTP_MESSAGES[type];
    const body = template
      .replace('{{appName}}', this.appName)
      .replace('{{code}}', code);

    const isWhatsApp = channel === 'whatsapp';
    const from = isWhatsApp
      ? `whatsapp:${TWILIO_WHATSAPP_SANDBOX_NUMBER}`
      : this.twilioPhoneSms;
    const toAddress = isWhatsApp ? `whatsapp:${to}` : to;
    const channelLabel = isWhatsApp ? 'WHATSAPP' : 'SMS';

    try {
      await this.twilioClient.messages.create({
        body,
        from,
        to: toAddress,
      });
      this.logger.log(
        `OTP enviado por ${channelLabel} a ${isWhatsApp ? toAddress : to}`,
      );
    } catch (err: unknown) {
      const error = err as { code?: number; message?: string; moreInfo?: string };
      this.logger.error(
        `Twilio error [canal=${channelLabel}] [${error.code ?? 'unknown'}]: ${error.message ?? err}. MoreInfo: ${error.moreInfo ?? 'n/a'}`,
      );
      throw new InternalServerErrorException({
        errorCode: 'MESSAGING_SERVICE_ERROR',
      });
    }
  }
}
