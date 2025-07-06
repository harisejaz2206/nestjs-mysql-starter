import { Column, Entity, Index } from 'typeorm';
import { CustomEntityBase } from '../../bases/_custom.entity.base';

/**
 * Audit Log Entity
 * 
 * Tracks all significant user actions and system events for compliance,
 * security monitoring, and debugging purposes.
 */
@Entity('audit_logs')
@Index(['userId', 'createdAt'])
@Index(['action', 'createdAt'])
@Index(['resource', 'createdAt'])
export class AuditLogEntity extends CustomEntityBase {
  @Column({ nullable: true })
  userId?: number;

  @Column({ length: 255 })
  action: string;

  @Column({ length: 255, nullable: true })
  resource?: string;

  @Column({ length: 45 })
  ipAddress: string;

  @Column({ length: 500, nullable: true })
  userAgent?: string;

  @Column({ type: 'int', default: 0 })
  duration: number; // in milliseconds

  @Column({ type: 'boolean', default: true })
  success: boolean;

  @Column({ type: 'json', nullable: true })
  metadata?: Record<string, any>;

  @Column({ length: 100, nullable: true })
  correlationId?: string;
} 