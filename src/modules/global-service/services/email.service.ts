import { ConfigService } from '@nestjs/config';
import { Injectable, InternalServerErrorException } from '@nestjs/common';
import * as sgMail from '@sendgrid/mail';
import { EnvKeysEnum } from 'src/modules/globals/enums/env.enum';
import { LoggerService } from './logger.service';

@Injectable()
export class EmailService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
  ) {
    const apiKey = this.configService.get(EnvKeysEnum.SendGridApiKey);
    if (apiKey) {
      sgMail.setApiKey(apiKey);
    }
  }

  /**
   * Send email using SendGrid dynamic template
   */
  async sendEmail<Template extends Record<string, any>>(
    to: string,
    templateId: string,
    dynamicTemplateData: Template,
  ): Promise<void> {
    try {
      // Add configurable sender information
      const enhancedData = {
        ...dynamicTemplateData,
        Sender_Name: this.configService.get('EMAIL_SENDER_NAME') || 'Your App',
        Sender_Address: this.configService.get('EMAIL_SENDER_ADDRESS') || '',
        Sender_City: this.configService.get('EMAIL_SENDER_CITY') || '',
        Sender_State: this.configService.get('EMAIL_SENDER_STATE') || '',
        Sender_Zip: this.configService.get('EMAIL_SENDER_ZIP') || '',
      };

      const msg = {
        to,
        from: this.configService.get(EnvKeysEnum.SenderEmail),
        templateId,
        dynamicTemplateData: enhancedData,
      };

      await sgMail.send(msg);
      this.logger.verbose(`Email sent to ${to} using template ${templateId}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}: ${error.message}`);
      throw new InternalServerErrorException(
        'Failed to send email: ' + error.message,
      );
    }
  }

  /**
   * Send simple email without template
   */
  async sendSimpleEmail(
    to: string,
    subject: string,
    text: string,
    html?: string,
  ): Promise<void> {
    try {
      const msg = {
        to,
        from: this.configService.get(EnvKeysEnum.SenderEmail),
        subject,
        text,
        html,
      };

      await sgMail.send(msg);
      this.logger.verbose(`Simple email sent to ${to} with subject: ${subject}`);
    } catch (error) {
      this.logger.error(`Failed to send simple email to ${to}: ${error.message}`);
      throw new InternalServerErrorException(
        'Failed to send email: ' + error.message,
      );
    }
  }
}
