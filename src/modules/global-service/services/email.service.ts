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
    sgMail.setApiKey(this.configService.get(EnvKeysEnum.SendGridApiKey)); // SendGrid API Key
  }

  async sendEmail<Template extends Record<string, any>>(
    to: string,
    templateId: string,
    dynamicTemplateData: Template,
  ): Promise<void> {
    try {
      dynamicTemplateData = {
        ...dynamicTemplateData,
        Sender_Name: 'Kean University Administration',
        Sender_Address: '1000 Morris Ave',
        Sender_City: 'Union',
        Sender_State: 'New Jersey, United States',
        Sender_Zip: '07083',
      };
      const msg = {
        to,
        from: this.configService.get(EnvKeysEnum.SenderEmail), // Sender email
        templateId, // SendGrid dynamic template ID
        dynamicTemplateData, // Template model
      };
      await sgMail.send(msg);
      this.logger.verbose(`Email sent to ${to} using template ${templateId}`);
    } catch (error) {
      throw new InternalServerErrorException(
        'Failed to send email: ' + error.message,
      );
    }
  }
}
