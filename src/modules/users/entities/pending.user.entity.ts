import { Column, Entity, Generated } from 'typeorm';
import { CustomEntityBase } from '../../bases/_custom.entity.base';

@Entity('pending_users')
export class PendingUserEntity extends CustomEntityBase {
  @Column({
    unique: true,
    nullable: false,
  })
  email: string;

  @Generated('uuid')
  @Column({
    unique: true,
    nullable: false,
  })
  token: string;
}
