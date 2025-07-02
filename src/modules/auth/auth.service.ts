import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { SigninUserDto } from './dto/signin-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { UsersService } from '../users/users.service';
import * as moment from 'moment';
import { GlobalHttpRequestService } from '../global-service/modules/global-http-request-module/global-http-request.service';

export interface RequestUserDto {
  email: string;
  id: number;
  createdAt: string;
  firstName: string;
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private readonly httpsService: GlobalHttpRequestService,
  ) {}
  async signIn(email: string, pass: string) {
    try {
      const firebaseURL = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`;

      const resp = await this.httpsService.postRequest(firebaseURL, {
        email,
        password: pass,
        returnSecureToken: true,
      });
      console.log(resp);
      return {
        email,
        accessToken: resp.idToken,
        expiresIn: parseInt(resp.expiresIn),
        expiresAt: moment().add(resp.expiresIn, 'seconds').format('LLLL'),
      };
    } catch (error) {
      console.log(
        'getFirebaseTokenByEmailAndPassword',
        error.response.data.error.errors,
      );
      throw new InternalServerErrorException(
        error?.response?.data?.error?.message ||
          error?.message ||
          'Unable to get firebase auth token',
      );
    }
  }
  create(createAuthDto: SigninUserDto) {
    console.log(createAuthDto);
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
