import {
  BadRequestException,
  HttpException,
  Injectable,
  OnModuleInit,
} from '@nestjs/common';
import firebase, { app, auth, credential } from 'firebase-admin';
import { Bucket } from '@google-cloud/storage';
import { LoggerService } from '../logger.service';

@Injectable()
export class FirebaseAdminService implements OnModuleInit {
  private firebaseApp: app.App;
  private firebaseBucket: Bucket;

  constructor(private readonly logger: LoggerService) {}

  async onModuleInit() {
    this.logger.log('Initializing firebase...');
    try {
      this.firebaseApp = firebase.initializeApp({
        credential: credential.cert(
          process.cwd() + '/firebase.service.account.json',
        ),
        // storageBucket: process.env.FIREBASE_STORAGE_BUCKET_PATH,
      });
      this.logger.verbose('Firebase initialized...');
      // this.firebaseBucket = this.firebaseApp.storage().bucket()
    } catch (e: any) {
      this.logger.error('Failed to initialize firebase', e);
      process.exit(1);
    }
  }

  async generateVerificationEmailLink(email: string) {
    return await this.firebaseApp.auth().generateEmailVerificationLink(email, {
      handleCodeInApp: true,
      url: process.env.FRONT_END_URL + '/login',
    });
  }

  async generatePasswordResetLink(email: string, continueURL: string) {
    const url = this.firebaseApp.auth().generatePasswordResetLink(email, {
      handleCodeInApp: true,
      url: continueURL,
    });
    return url;
  }

  async getUserByEmail(email: string): Promise<auth.UserRecord> {
    try {
      return await this.firebaseApp.auth().getUserByEmail(email);
    } catch (e) {
      if (e.code === 'auth/user-not-found') {
        return undefined;
      }
      throw e;
    }
  }

  async createCustomToken(uuid: string) {
    try {
      return await this.firebaseApp.auth().createCustomToken(uuid);
    } catch (e) {
      throw e;
    }
  }

  async createUser(
    name: string,
    email: string,
    password: string,
    emailVerified = false,
  ): Promise<auth.UserRecord> {
    return await this.firebaseApp.auth().createUser({
      displayName: name,
      email,
      emailVerified: emailVerified,
      password,
    });
  }

  async deleteUser(uid: string) {
    return await this.firebaseApp.auth().deleteUser(uid);
  }

  async sendVerificationEmail(email: string) {
    const user = await this.getUserByEmail(email);
    if (user) {
      const link = await this.generateVerificationEmailLink(email);
      return link;
    }
  }

  async updateEmail(uuid: string, email: string) {
    try {
      const user = await this.firebaseApp.auth().getUser(uuid);
      await this.firebaseApp
        .auth()
        .updateUser(uuid, {
          email: email,
          emailVerified: user.providerData[0]?.providerId !== 'password',
        })
        .then(async () => {
          if (user.providerData[0]?.providerId === 'password') {
            const link = await this.generateVerificationEmailLink(email);
            return link;
          }
        })
        .catch((error: any) => {
          if (error.code === 'auth/email-already-exists') {
            throw new HttpException(error.message, 400);
          }
        });
      return true;
    } catch (e) {
      if (e.code === 'auth/user-not-found') {
        return;
      }
      throw e;
    }
  }

  async updatePassword(uid: string, password: string) {
    try {
      const user = await this.firebaseApp.auth().getUser(uid);
      if (user && user.providerData[0]?.providerId === 'password') {
        return await this.firebaseApp.auth().updateUser(uid, {
          password: password,
        });
      } else {
        throw new BadRequestException(
          'Customer Signed in as Social Login. Password cannot be updated',
        );
      }
    } catch (e) {
      if (e.code === 'auth/user-not-found') {
        return;
      }
      throw e;
    }
  }

  async ping() {
    try {
      await this.firebaseApp.auth().getUserByEmail('abc@xyz.com');
    } catch (e) {
      if (e.code === 'auth/user-not-found') {
        return;
      }
      throw e;
    }
  }

  async getSignedUrlFromFirebaseStorage(
    filePathOrName: string,
  ): Promise<string> {
    try {
      const file = this.firebaseBucket.file(filePathOrName);
      const [url] = await file.getSignedUrl({
        action: 'read',
        expires: Date.now() + 1000 * 60 * 60 * 24 * 365 * 100, // 100 years
      });
      return url;
    } catch (err) {
      throw err;
    }
  }

  async uploadFileToFirebaseStorageAndReturnLink(
    file: string | Buffer,
    filePathOrName: string,
  ): Promise<string> {
    try {
      await this.firebaseApp.storage().bucket().file(filePathOrName).save(file);
      // return FirebaseService.getSignedUrlFromFirebaseStorage(filePathOrName);
      return '';
    } catch (err) {
      throw err;
    }
  }

  async deleteFileFromFirebaseStorage(filePathOrName: string) {
    try {
      await this.firebaseApp.storage().bucket().file(filePathOrName).delete();
    } catch (err) {
      throw err;
    }
  }

  async verifyIdToken(idToken: string) {
    try {
      const dec = await this.firebaseApp.auth().verifyIdToken(idToken);
      return dec;
    } catch (e) {
      throw e;
    }
  }
}
