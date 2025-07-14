import { MigrationInterface, QueryRunner } from "typeorm";

export class AddTokenVersionUserEntity1752479975837 implements MigrationInterface {
    name = 'AddTokenVersionUserEntity1752479975837'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`tokenVersion\` int NOT NULL DEFAULT '0'`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`tokenVersion\``);
    }

}
