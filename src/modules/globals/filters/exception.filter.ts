import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { GlobalResponseDto } from '../dtos/global.response.dto';
import { isString } from 'class-validator';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  async catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    // const request = ctx.getRequest<Request>();
    const isHttpExceptionObj = exception instanceof HttpException;
    const status = isHttpExceptionObj
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;
    console.error('HttpExceptionFilter -> catch -> exception', exception);
    const message = isHttpExceptionObj ? exception.getResponse() : exception;
    const errorResponse = new GlobalResponseDto(
      status,
      isHttpExceptionObj
        ? isString(message)
          ? message
          : message['error']
        : 'Unhandled Exception Occured',
      exception.message,
      message['message'],
      {
        reqPath: request?.originalUrl,
        reMethod: request?.method,
        reqPayload: request?.body,
      },
    );

    response.status(status).json(errorResponse);
  }
}
