import { AfterLoad, BeforeInsert, BeforeUpdate, Column, Entity } from 'typeorm';
import { CustomEntityBase } from '../../bases/_custom.entity.base';
import { UsersStatusEnum } from '../enums/users.status.enum';
import { UserRoleEnum } from '../enums/user-enums.enum';

@Entity('user')
export class UserEntity extends CustomEntityBase {
  @Column({
    nullable: true,
  })
  lastApiCallAt: Date;

  @Column({
    nullable: false,
  })
  firstName: string;

  @Column({
    nullable: true,
  })
  lastName: string;

  @Column({
    nullable: false,
    unique: true,
  })
  email: string;

  @Column({
    nullable: true,
    select: false,
  })
  password?: string;

  @Column({
    nullable: true,
  })
  phoneNumber: string;

  @Column({
    nullable: true,
  })
  country: string;

  @Column({
    nullable: true,
  })
  state: string;

  @Column({
    type: 'enum',
    enum: UserRoleEnum,
    default: UserRoleEnum.User,
  })
  role: UserRoleEnum;

  @Column({
    type: 'enum',
    enum: UsersStatusEnum,
    default: UsersStatusEnum.ACTIVE,
  })
  status: UsersStatusEnum;

  @Column({
    nullable: false,
    type: 'boolean',
    default: false,
  })
  isEmailVerified: boolean;

  @Column({
    nullable: true,
    type: 'int',
  })
  otp: number;

  @Column({
    nullable: true,
    type: 'bigint',
  })
  otpExpireAt: number;

  @Column({
    nullable: true,
  })
  avatar: string;

  @Column({
    nullable: true,
  })
  emailVerifiedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  emailToLowerCase() {
    if (this.email) {
      this.email = this.email.toLowerCase();
    }
  }

  /**
   * Get full name of the user
   */
  get fullName(): string {
    return `${this.firstName}${this.lastName ? ' ' + this.lastName : ''}`;
  }

  @AfterLoad()
  afterLoad() {
    // Reserved for future data transformation needs
  }
}
