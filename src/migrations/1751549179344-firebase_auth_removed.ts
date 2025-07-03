import { MigrationInterface, QueryRunner } from "typeorm";

export class FirebaseAuthRemoved1751549179344 implements MigrationInterface {
    name = 'FirebaseAuthRemoved1751549179344'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` DROP FOREIGN KEY \`FK_c28e52f758e7bbc53828db92194\``);
        await queryRunner.query(`ALTER TABLE \`pending_users\` DROP FOREIGN KEY \`FK_e83aefe06386db826ecca59395b\``);
        await queryRunner.query(`DROP INDEX \`IDX_f35b4c7507eb7d48531dd7c753\` ON \`user\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`fUId\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`isUserEmailVerified\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`roleId\``);
        await queryRunner.query(`ALTER TABLE \`pending_users\` DROP COLUMN \`roleId\``);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`password\` varchar(255) NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`role\` enum ('admin', 'user') NOT NULL DEFAULT 'user'`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`isEmailVerified\` tinyint NOT NULL DEFAULT 0`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`otp\` int NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`otpExpireAt\` bigint NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`avatar\` varchar(255) NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`emailVerifiedAt\` datetime NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`emailVerifiedAt\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`avatar\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`otpExpireAt\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`otp\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`isEmailVerified\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`role\``);
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`password\``);
        await queryRunner.query(`ALTER TABLE \`pending_users\` ADD \`roleId\` int NOT NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`roleId\` int NOT NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`isUserEmailVerified\` tinyint NOT NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`fUId\` varchar(255) NOT NULL`);
        await queryRunner.query(`CREATE UNIQUE INDEX \`IDX_f35b4c7507eb7d48531dd7c753\` ON \`user\` (\`fUId\`)`);
        await queryRunner.query(`ALTER TABLE \`pending_users\` ADD CONSTRAINT \`FK_e83aefe06386db826ecca59395b\` FOREIGN KEY (\`roleId\`) REFERENCES \`user_roles\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD CONSTRAINT \`FK_c28e52f758e7bbc53828db92194\` FOREIGN KEY (\`roleId\`) REFERENCES \`user_roles\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

}
