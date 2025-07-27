/*
  Warnings:

  - You are about to drop the column `user_id` on the `organizations` table. All the data in the column will be lost.
  - You are about to drop the column `user_id` on the `projects` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "organizations" DROP CONSTRAINT "organizations_user_id_fkey";

-- DropForeignKey
ALTER TABLE "projects" DROP CONSTRAINT "projects_user_id_fkey";

-- AlterTable
ALTER TABLE "organizations" DROP COLUMN "user_id",
ADD COLUMN     "owner_id" TEXT;

-- AlterTable
ALTER TABLE "projects" DROP COLUMN "user_id",
ADD COLUMN     "owner_id" TEXT;

-- AddForeignKey
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
