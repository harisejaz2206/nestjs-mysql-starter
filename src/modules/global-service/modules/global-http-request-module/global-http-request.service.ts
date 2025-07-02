import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { Injectable } from '@nestjs/common';
import { LoggerService } from '../../services/logger.service';

@Injectable()
export class GlobalHttpRequestService {
  constructor(
    private httpService: HttpService,
    private readonly logger: LoggerService,
  ) {}

  async getRequest(url: string, headers?: Record<any, any>) {
    this.logger.log('sending GET request on ', `'${url}' with headers`);
    const { data } = await firstValueFrom(
      this.httpService.get(url, {
        headers,
      }),
    );
    return data;
  }

  async postRequest(url: string, body = {}, headers?: Record<any, any>) {
    this.logger.log(
      'sending POST request on ' +
        `${url} with formdata ${
          body?.['secret']
            ? '[Body is omitted from logs due to security issues]'
            : JSON.stringify(body)
        }`,
    );
    const { data } = await firstValueFrom(
      this.httpService.post(url, body, { headers }),
    );
    return data;
  }

  async putRequest(url: string, body = {}, headers?: Record<any, any>) {
    this.logger.log(
      'sending PUT request on ',
      `'${url}' and payload ${JSON.stringify(body)} `,
    );
    const { data } = await firstValueFrom(
      this.httpService.put(url, body, { headers }),
    );
    return data;
  }

  async deleteRequest(url: string, headers?: Record<any, any>) {
    this.logger.log('sending DELETE request on ', `'${url}'`);
    const { data } = await firstValueFrom(
      this.httpService.delete(url, { headers }),
    );
    return data;
  }
}
