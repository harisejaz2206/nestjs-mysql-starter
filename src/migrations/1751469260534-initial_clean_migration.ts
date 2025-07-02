import { MigrationInterface, QueryRunner } from "typeorm";

export class InitialCleanMigration1751469260534 implements MigrationInterface {
    name = 'InitialCleanMigration1751469260534'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`user_role_permissions\` (\`id\` int NOT NULL AUTO_INCREMENT, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deletedAt\` datetime(6) NULL, \`resource\` varchar(255) NOT NULL, \`create\` tinyint NOT NULL DEFAULT 0, \`read\` tinyint NOT NULL DEFAULT 0, \`update\` tinyint NOT NULL DEFAULT 0, \`delete\` tinyint NOT NULL DEFAULT 0, \`roleId\` int NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`pending_users\` (\`id\` int NOT NULL AUTO_INCREMENT, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deletedAt\` datetime(6) NULL, \`email\` varchar(255) NOT NULL, \`token\` varchar(36) NOT NULL, \`roleId\` int NOT NULL, UNIQUE INDEX \`IDX_52d88bd887025f9814da7d2845\` (\`email\`), UNIQUE INDEX \`IDX_a2c8ee1777824e674712ecf4df\` (\`token\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`user_roles\` (\`id\` int NOT NULL AUTO_INCREMENT, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deletedAt\` datetime(6) NULL, \`name\` varchar(255) NOT NULL, \`slug\` varchar(255) NULL, UNIQUE INDEX \`IDX_4a77d431a6b2ac981c342b13c9\` (\`name\`), UNIQUE INDEX \`IDX_e32a6a220616506d7a62d5330a\` (\`slug\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`user\` (\`id\` int NOT NULL AUTO_INCREMENT, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deletedAt\` datetime(6) NULL, \`fUId\` varchar(255) NOT NULL, \`isUserEmailVerified\` tinyint NOT NULL, \`lastApiCallAt\` datetime NULL, \`firstName\` varchar(255) NOT NULL, \`lastName\` varchar(255) NULL, \`email\` varchar(255) NOT NULL, \`phoneNumber\` varchar(255) NULL, \`country\` varchar(255) NULL, \`state\` varchar(255) NULL, \`status\` enum ('active', 'pending', 'suspended') NOT NULL DEFAULT 'active', \`roleId\` int NOT NULL, UNIQUE INDEX \`IDX_f35b4c7507eb7d48531dd7c753\` (\`fUId\`), UNIQUE INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` (\`email\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`ALTER TABLE \`user_role_permissions\` ADD CONSTRAINT \`FK_4eb5a06d455bbb8da0c0a67d37a\` FOREIGN KEY (\`roleId\`) REFERENCES \`user_roles\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`pending_users\` ADD CONSTRAINT \`FK_e83aefe06386db826ecca59395b\` FOREIGN KEY (\`roleId\`) REFERENCES \`user_roles\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`user\` ADD CONSTRAINT \`FK_c28e52f758e7bbc53828db92194\` FOREIGN KEY (\`roleId\`) REFERENCES \`user_roles\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` DROP FOREIGN KEY \`FK_c28e52f758e7bbc53828db92194\``);
        await queryRunner.query(`ALTER TABLE \`pending_users\` DROP FOREIGN KEY \`FK_e83aefe06386db826ecca59395b\``);
        await queryRunner.query(`ALTER TABLE \`user_role_permissions\` DROP FOREIGN KEY \`FK_4eb5a06d455bbb8da0c0a67d37a\``);
        await queryRunner.query(`DROP INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` ON \`user\``);
        await queryRunner.query(`DROP INDEX \`IDX_f35b4c7507eb7d48531dd7c753\` ON \`user\``);
        await queryRunner.query(`DROP TABLE \`user\``);
        await queryRunner.query(`DROP INDEX \`IDX_e32a6a220616506d7a62d5330a\` ON \`user_roles\``);
        await queryRunner.query(`DROP INDEX \`IDX_4a77d431a6b2ac981c342b13c9\` ON \`user_roles\``);
        await queryRunner.query(`DROP TABLE \`user_roles\``);
        await queryRunner.query(`DROP INDEX \`IDX_a2c8ee1777824e674712ecf4df\` ON \`pending_users\``);
        await queryRunner.query(`DROP INDEX \`IDX_52d88bd887025f9814da7d2845\` ON \`pending_users\``);
        await queryRunner.query(`DROP TABLE \`pending_users\``);
        await queryRunner.query(`DROP TABLE \`user_role_permissions\``);
    }

}
