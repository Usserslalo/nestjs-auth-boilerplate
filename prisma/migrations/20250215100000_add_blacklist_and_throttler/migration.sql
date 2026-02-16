-- CreateTable
CREATE TABLE "BlacklistedToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlacklistedToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThrottlerRecord" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "throttlerName" TEXT NOT NULL,
    "totalHits" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "blockExpiresAt" TIMESTAMP(3),
    "isBlocked" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "ThrottlerRecord_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "BlacklistedToken_tokenHash_key" ON "BlacklistedToken"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "ThrottlerRecord_key_throttlerName_key" ON "ThrottlerRecord"("key", "throttlerName");
