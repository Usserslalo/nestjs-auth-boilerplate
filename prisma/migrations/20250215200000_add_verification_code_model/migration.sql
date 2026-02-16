-- CreateEnum
CREATE TYPE "VerificationCodeType" AS ENUM ('REGISTER', 'PASSWORD_RESET');

-- CreateTable
CREATE TABLE "VerificationCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "type" "VerificationCodeType" NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VerificationCode_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "VerificationCode_userId_type_idx" ON "VerificationCode"("userId", "type");

-- AddForeignKey
ALTER TABLE "VerificationCode" ADD CONSTRAINT "VerificationCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AlterTable: eliminar columnas antiguas de OTP en User (si existen)
ALTER TABLE "User" DROP COLUMN IF EXISTS "verificationCode";
ALTER TABLE "User" DROP COLUMN IF EXISTS "verificationExpires";
ALTER TABLE "User" DROP COLUMN IF EXISTS "resetPasswordCode";
ALTER TABLE "User" DROP COLUMN IF EXISTS "resetPasswordExpires";
