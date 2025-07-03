import { IToken } from './auth-token.interface';
import { IAuthUser } from './auth-user.interface';

export interface ILogin {
  user: IAuthUser;
  token: IToken;
} 