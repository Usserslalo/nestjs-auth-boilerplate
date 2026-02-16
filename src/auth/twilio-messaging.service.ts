import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Twilio from 'twilio';
import { ErrorCode } from '../common/constants/error-codes';
import {
  MessagingService,
  type MessagingChannel,
  type OtpType,
} from './messaging.service';

const OTP_MESSAGES: Record<OtpType, string> = {
  register:
    'Este es tu código para verificar tu cuenta en {{appName}}: {{code}}. Expira en 10 minutos.',
  password_reset:
    'Este es tu código para restablecer tu contraseña en {{appName}}: {{code}}. Expira en 10 minutos.',
};

/** Número del Sandbox de WhatsApp de Twilio (join code en el chat para activar). */
const TWILIO_WHATSAPP_SANDBOX_NUMBER = '+14155238886';

/**
 * Implementación real de mensajería vía Twilio (SMS o WhatsApp).
 * Solo debe usarse cuando TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN y TWILIO_PHONE_NUMBER están configurados.
 */
@Injectable()
export class TwilioMessagingService extends MessagingService {
  private readonly logger = new Logger(TwilioMessagingService.name);
  private readonly twilioClient: Twilio.Twilio;
  private readonly twilioPhoneSms: string;
  private readonly appName: string;

  constructor(private readonly config: ConfigService) {
    super();
    const accountSid = this.config.getOrThrow<string>('TWILIO_ACCOUNT_SID');
    const authToken = this.config.getOrThrow<string>('TWILIO_AUTH_TOKEN');
    this.twilioPhoneSms = this.config.getOrThrow<string>('TWILIO_PHONE_NUMBER');
    this.appName = this.config.getOrThrow<string>('APP_NAME');
    this.twilioClient = Twilio(accountSid, authToken);
  }

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
        errorCode: ErrorCode.MESSAGING_SERVICE_ERROR,
      });
    }
  }
}
