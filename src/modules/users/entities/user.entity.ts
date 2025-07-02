import { AfterLoad, Column, Entity, ManyToOne, OneToOne } from 'typeorm';
import { CustomEntityBase } from '../../bases/_custom.entity.base';
import { UsersStatusEnum } from '../enums/users.status.enum';

@Entity('user')
export class UserEntity extends CustomEntityBase {
  /**
   * Firebase User ID
   * This is the unique identifier of the user in Firebase
   */
  @Column({
    nullable: false,
    unique: true,
  })
  fUId: string;

  @Column({
    nullable: false,
    type: 'boolean',
  })
  isUserEmailVerified: boolean;

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
    nullable: true,
  })
  role: string;

  @Column({
    type: 'enum',
    enum: UsersStatusEnum,
    default: UsersStatusEnum.ACTIVE,
  })
  status: UsersStatusEnum;

  public roleSlug: string;

  @AfterLoad()
  afterLoad() {
    // if (this.role?.id) {
    //   this.roleSlug = this.role.slug;
    // }
  }
}
