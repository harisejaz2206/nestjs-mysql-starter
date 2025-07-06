import { MigrationInterface, QueryRunner } from "typeorm";

export class AuditLogs1751791034739 implements MigrationInterface {
    name = 'AuditLogs1751791034739'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`audit_logs\` (\`id\` int NOT NULL AUTO_INCREMENT, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deletedAt\` datetime(6) NULL, \`userId\` int NULL, \`action\` varchar(255) NOT NULL, \`resource\` varchar(255) NULL, \`ipAddress\` varchar(45) NOT NULL, \`userAgent\` varchar(500) NULL, \`duration\` int NOT NULL DEFAULT '0', \`success\` tinyint NOT NULL DEFAULT 1, \`metadata\` json NULL, \`correlationId\` varchar(100) NULL, INDEX \`IDX_62fd8c2a24d920f1f23aa312e3\` (\`resource\`, \`createdAt\`), INDEX \`IDX_0ec936941eb8556fcd7a1f0eae\` (\`action\`, \`createdAt\`), INDEX \`IDX_99e589da8f9e9326ee0d01a028\` (\`userId\`, \`createdAt\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX \`IDX_99e589da8f9e9326ee0d01a028\` ON \`audit_logs\``);
        await queryRunner.query(`DROP INDEX \`IDX_0ec936941eb8556fcd7a1f0eae\` ON \`audit_logs\``);
        await queryRunner.query(`DROP INDEX \`IDX_62fd8c2a24d920f1f23aa312e3\` ON \`audit_logs\``);
        await queryRunner.query(`DROP TABLE \`audit_logs\``);
    }

}
