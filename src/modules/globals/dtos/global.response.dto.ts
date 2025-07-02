import { HttpStatus } from '@nestjs/common';

export class GlobalResponseDto<T> {
  message: string;
  statusCode: number;
  data: T;
  error?: T;
  errorOptions?: any;

  constructor(
    status: HttpStatus,
    message: string,
    data: T,
    error?: any,
    errOptions?: any,
  ) {
    this.statusCode = status;
    this.message = message;
    if (status >= 200 && status < 300) {
      this.data = data;
    } else {
      this.data = null;
      this.error = error || data;
      this.errorOptions = errOptions;
    }
  }
}
