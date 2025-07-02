import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreateSuperAdminUserDto } from './dto/create-super-admin-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from './entities/user.entity';
import { Brackets, Repository } from 'typeorm';
import { RequestContext } from 'nestjs-request-context';
import { UserRoleEnum } from './enums/user-enums.enum';
import { FirebaseAdminService } from '../global-service/services/firebase/firebase.admin.service';
import { Transactional } from 'typeorm-transactional';
import { CreateUserDto } from './dto/create-user.dto';
import { PendingUserEntity } from './entities/pending.user.entity';
import { EmailService } from '../global-service/services/email.service';
import { EmailTemplates } from '../global-service/enums/email.templates.enum';
import { ConfigService } from '@nestjs/config';
import { EnvKeysEnum } from '../globals/enums/env.enum';
import { FirebaseUserRecord } from 'express';
import { SignupUpUserDto } from './dto/signup-up-user.dto';
import { UsersStatusEnum } from './enums/users.status.enum';
import { Try } from '../globals/helpers/try-catch.helpers';
import { UpdateUserForMgmt } from './dto/update-user.dto';
import { UsersListDto } from './dto/users-list.dto';
import { ListDataDto } from '../globals/dtos/response.data.dtos';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
    @InjectRepository(PendingUserEntity)
    private readonly pendingUserRepo: Repository<PendingUserEntity>,
    private readonly firebaseAdminService: FirebaseAdminService,
    private readonly emailService: EmailService,  
    private readonly configService: ConfigService,
  ) {}

  getRepo() {
    return this.userRepo;
  }

  getRequestUser(): UserEntity {
    const req: any = RequestContext.currentContext.req;
    if (req.user) {
      return {
        ...req.user,
      } as UserEntity;
    }
    throw new BadRequestException('User not found in the request!');
  }

  async getCurrentUser(relations?: string[]): Promise<UserEntity> {
    const reqUser = this.getRequestUser();
    const user = await this.userRepo.findOne({
      where: {
        id: reqUser.id,
      },
      relations,
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async updateUserStatus(
    userId: number,
    status: UsersStatusEnum,
  ): Promise<UserEntity> {
    return Try(async () => {
      const currentUser = this.getRequestUser();
      if (currentUser.id === userId) {
        throw new BadRequestException('You cannot update your own status');
      }
      let user = await this.findOne(userId, true);
      if (status === user.status) {
        throw new BadRequestException(`User is already ${status}`);
      }
      user.status = status;
      user = await user.save({
        reload: true,
      });
      return user;
    }).Catch();
  }

  async updateUserForMgmt(
    userId: number,
    body: UpdateUserForMgmt,
  ): Promise<UserEntity> {
    return Try(async () => {
      const currentUser = this.getRequestUser();
      let user = await this.findOne(userId, true, ['role']);
      if (currentUser.id === userId) {
        throw new BadRequestException('You cannot update your own role');
      }
      // if (body.role === user.role.id) {
      //   throw new BadRequestException(
      //     `Duplicate role assignment. User already has this role.`,
      //   );
      // }
      user = await user.save({
        reload: true,
      });
      return user;
    }).Catch();
  }

  async getFirebaseUserInCurrentRequest(): Promise<FirebaseUserRecord> {
    const req: any = RequestContext.currentContext.req;
    if (req.firebaseUser) {
      return req.firebaseUser;
    }
    throw new BadRequestException('Firebase user not found in the request!');
  }

  /*
/**
   * @deprecated This method is deprecated and will be removed in future versions.
   */
  @Transactional()
  async createUserOld(
    createUserDto: CreateSuperAdminUserDto,
    role = UserRoleEnum.SuperAdmin,
  ): Promise<UserEntity> {
    try {
      const firebaseUser = await this.firebaseAdminService.createUser(
        createUserDto.firstName,
        createUserDto.email,
        createUserDto.password,
      );
      const savedUser = await this.userRepo.save({
        fUId: firebaseUser.uid,
        firstName: createUserDto.firstName,
        email: createUserDto.email,
        isUserEmailVerified: firebaseUser.emailVerified,
      });
      return savedUser;
    } catch (e) {
      throw new InternalServerErrorException(
        e?.message || ' Failed to create user',
      );
    }
  }

  async resendInviteEmail(id: number): Promise<PendingUserEntity> {
    try {
      const pendingUser = await this.pendingUserRepo.findOne({
        where: {
          id,
        },
      });
      if (!pendingUser) {
        throw new NotFoundException('Pending user not found');
      }
      await this.sendOrResendPendingUserInviteEmail(pendingUser.email);
      return pendingUser;
    } catch (e) {
      throw new InternalServerErrorException(
        e?.message || ' Failed to resend invite email',
      );
    }
  }

  private async sendOrResendPendingUserInviteEmail(
    email: string,
  ): Promise<void> {
    try {
      const pendingUser = await this.pendingUserRepo.findOne({
        where: {
          email,
        },
        relations: ['role'],
      });
      if (!pendingUser) {
        throw new NotFoundException('Pending user not found');
      }
      const link = new URL(
        '/users/auth/signup/' + pendingUser.token,
        this.configService.getOrThrow(EnvKeysEnum.KeanFrontendUrl),
      );
      // set query parameters
      link.searchParams.set('email', pendingUser.email);
      // Send email logic here
      // await this.emailService.sendEmail<{
      //   signup_link: string;
      //   user_role: string;
      // }>(email, EmailTemplates.UserInvite, {
      //   signup_link: link.toString(),
      //   // user_role: pendingUser.role.name,
      // });
    } catch (e) {
      throw new InternalServerErrorException(
        e?.message || ' Failed to send or resent pending user invite email',
      );
    }
  }

  @Transactional()
  async createUser(body: CreateUserDto): Promise<PendingUserEntity> {
    try {
      const pendingUser = this.pendingUserRepo.create({
        email: body.email,
      });
      const savedUser = await this.pendingUserRepo.save(pendingUser);
      await this.sendOrResendPendingUserInviteEmail(body.email);
      return savedUser;
    } catch (e) {
      throw new InternalServerErrorException(
        e?.message || ' Failed to create user',
      );
    }
  }

  @Transactional()
  async signupPendingUser(
    pendingUserToken: string,
    firebaseUser: FirebaseUserRecord,
    body: SignupUpUserDto,
  ) {
    try {
      const pendingUser = await this.pendingUserRepo.findOne({
        where: {
          token: pendingUserToken,
        },
      });
      if (!pendingUser) {
        throw new NotFoundException('Invalid invite token');
      }
      if (firebaseUser.email !== pendingUser.email) {
        throw new BadRequestException(
          'Authenticated user email does not match the pending user email',
        );
      }
      const user = this.userRepo.create({
        fUId: firebaseUser.uid,
        firstName: body.firstName,
        email: pendingUser.email,
        isUserEmailVerified: firebaseUser.emailVerified || true,
        lastName: body.lastName,
        phoneNumber: body.phoneNumber,
        country: body.country,
        state: body.state,
      });
      const savedUser = await this.userRepo.save(user);
      await this.pendingUserRepo.remove(pendingUser);
      return savedUser;
    } catch (e) {
      throw new InternalServerErrorException(
        e?.message || 'Failed to signup pending user',
      );
    }
  }

  async findAll(
    query: UsersListDto,
  ): Promise<ListDataDto<UserEntity | PendingUserEntity>> {
    let { search: search, role, status, page, perPage } = query;
    search = search?.trim()?.toLowerCase();
    role = role?.trim()?.toLowerCase();
    // Query active users
    const userQuery = this.userRepo
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.role', 'role');

    if (search) {
      userQuery.andWhere(
        new Brackets((qb) => {
          qb.where('user.email LIKE :search', { search: `%${search}%` })
            .orWhere('user.firstName LIKE :search', { search: `%${search}%` })
            .orWhere('user.lastName LIKE :search', { search: `%${search}%` });
        }),
      );
    }

    if (role) {
      if (role) {
        userQuery.andWhere(
          new Brackets((qb) => {
            qb.where('LOWER(role.name) = :role', { role }).orWhere(
              'LOWER(role.slug) = :role',
              { role },
            );
          }),
        );
      }
    }

    if (status) {
      userQuery.andWhere('user.status = :status', { status });
    }

    let combinedResults: Array<UserEntity | PendingUserEntity> =
      await userQuery.getMany();
    let pendingUsers: PendingUserEntity[] = [];
    if (status === UsersStatusEnum.PENDING || !status) {
      // Query pending users
      const pendingUserQuery = this.pendingUserRepo
        .createQueryBuilder('pendingUser')
        .leftJoinAndSelect('pendingUser.role', 'role');

      if (search) {
        pendingUserQuery.andWhere('pendingUser.email LIKE :search', {
          search: `%${search}%`,
        });
      }

      if (role) {
        pendingUserQuery.andWhere(
          new Brackets((qb) => {
            qb.where('LOWER(role.name = :role)', { role }).orWhere(
              'LOWER(role.slug) = :role',
              { role },
            );
          }),
        );
      }

      pendingUsers = await pendingUserQuery.getMany();

      // Combine results
      combinedResults.push(...pendingUsers);

      // Sort combined results (optional, e.g., by creation date)
      combinedResults.sort((a, b) => (a.createdAt > b.createdAt ? -1 : 1));
    }
    // Apply pagination
    const startIndex = page * perPage;
    const paginatedResults = combinedResults.slice(
      startIndex,
      startIndex + perPage,
    );

    return {
      results: paginatedResults,
      pagination: {
        totalCount: combinedResults.length,
        page: page, // Adjusting to 1-based index
        perPage,
      },
      filters: {
        searchString: search,
        role: role,
        status: status,
      },
    };
  }

  async findOne(id: number, validateIfExits = false, rels: string[] = []) {
    if (!id) {
      throw new BadRequestException('Id is required');
    }
    const user = await this.userRepo.findOne({
      where: {
        id,
      },
      relations: rels,
    });
    if (!user && validateIfExits) {
      throw new NotFoundException(`User not found against id ${id}`);
    }
    return user;
  }

  async findByEmail(email: string, validateIfExits = false) {
    const user = await this.userRepo.findOne({
      where: {
        email,
      },
    });
    if (!user && validateIfExits) {
      throw new NotFoundException(`User not found against email ${email}`);
    }
    return user;
  }

  async findByFirebaseId(
    fUId: string,
    validateIfExits = false,
    rels: string[] = [],
  ) {
    const user = await this.userRepo.findOne({
      where: {
        fUId: fUId,
      },
      relations: rels,
    });
    if (!user && validateIfExits) {
      throw new NotFoundException(
        `User not found against firebase user ID ${fUId}`,
      );
    }
    return user;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
