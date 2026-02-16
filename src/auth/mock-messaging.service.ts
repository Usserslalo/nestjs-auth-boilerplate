import { Injectable, Logger } from '@nestjs/common';
import {
  MessagingService,
  type MessagingChannel,
  type OtpType,
} from './messaging.service';

/**
 * Implementación mock que escribe el OTP en consola.
 * Se usa cuando no hay credenciales de Twilio o en desarrollo.
 */
@Injectable()
export class MockMessagingService extends MessagingService {
  private readonly logger = new Logger(MockMessagingService.name);

  async sendOtp(
    to: string,
    code: string,
    channel: MessagingChannel = 'sms',
    _type?: OtpType,
  ): Promise<void> {
    const channelLabel = channel === 'whatsapp' ? 'WhatsApp' : 'SMS';
    this.logger.log(
      `[MOCK MESSAGING] Enviando OTP ${code} a ${to} vía ${channelLabel}`,
    );
  }
}
