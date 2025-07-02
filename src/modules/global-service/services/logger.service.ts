import { Inject, Injectable, Scope } from '@nestjs/common';
import { INQUIRER } from '@nestjs/core';
import { RequestContext } from 'nestjs-request-context';
import { UserEntity } from '../../users/entities/user.entity';
import { CustomLogger } from '../../globals/CustomLogger';

@Injectable({
  scope: Scope.TRANSIENT,
})
export class LoggerService extends CustomLogger {
  constructor(@Inject(INQUIRER) private readonly inquirer: object) {
    super();
    const user = RequestContext?.currentContext?.req?.user as
      | UserEntity
      | undefined;
    if (user) {
      this.setContext(`${this.inquirer?.constructor?.name}`);
    } else {
      this.setContext(this.inquirer?.constructor?.name || 'ConsoleLogger ');
    }
  }
}
