import { ConsoleLogger } from '@nestjs/common';
import { RequestService } from '../global-service/services/request.service';

export class CustomLogger extends ConsoleLogger {
  log(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.log(
        `REQ-ID: ${RequestService.getRequestId() || ''} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.log(message, ...optionalParams);
    }
  }

  error(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.error(
        `REQ-ID: ${RequestService.getRequestId() || ''} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.error(message, ...optionalParams);
    }
  }

  /**
   * Write a 'warn' level log.
   */
  warn(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.warn(
        `REQ-ID: ${RequestService.getRequestId() || ''} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.warn(message, ...optionalParams);
    }
  }

  /**
   * Write a 'debug' level log.
   */
  debug(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.debug(
        `REQ-ID: ${RequestService.getRequestId() || ''} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.debug(message, ...optionalParams);
    }
  }

  /**
   * Write a 'verbose' level log.
   */
  verbose(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.verbose(
        `REQ-ID: ${RequestService.getRequestId() || ''} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.verbose(message, ...optionalParams);
    }
  }
}
