import { Injectable } from '@nestjs/common';
import { RequestContext } from 'nestjs-request-context';

@Injectable()
export class RequestService {
  public static getRequestId(): string {
    try {
      const req: any = RequestContext.currentContext.req;
      if (req['reqId']) {
        return String(req['reqId']);
      }
    } catch {
      //
    }
    return undefined;
  }
}
