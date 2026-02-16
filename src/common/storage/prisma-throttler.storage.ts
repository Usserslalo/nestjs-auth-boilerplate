import { Injectable } from '@nestjs/common';
import { ThrottlerStorage } from '@nestjs/throttler';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class PrismaThrottlerStorage implements ThrottlerStorage {
  constructor(private readonly prisma: PrismaService) {}

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): Promise<{ totalHits: number; timeToExpire: number; isBlocked: boolean; timeToBlockExpire: number }> {
    const now = Date.now();
    const ttlMs = ttl;
    const blockMs = blockDuration;
    const newExpiresAt = new Date(now + ttlMs);

    let record = await this.prisma.throttlerRecord.findUnique({
      where: { key_throttlerName: { key, throttlerName } },
    });

    if (!record) {
      record = await this.prisma.throttlerRecord.create({
        data: {
          key,
          throttlerName,
          totalHits: 0,
          expiresAt: newExpiresAt,
          blockExpiresAt: null,
          isBlocked: false,
        },
      });
    }

    let totalHits = record.totalHits;
    let isBlocked = record.isBlocked;
    let expiresAt = record.expiresAt;
    let blockExpiresAt = record.blockExpiresAt;

    const timeToExpire = Math.ceil((expiresAt.getTime() - now) / 1000);
    const timeToBlockExpire = blockExpiresAt
      ? Math.ceil((blockExpiresAt.getTime() - now) / 1000)
      : 0;

    if (timeToExpire <= 0) {
      totalHits = 0;
      expiresAt = newExpiresAt;
      await this.prisma.throttlerRecord.update({
        where: { id: record.id },
        data: { expiresAt, totalHits: 0 },
      });
    }

    if (timeToBlockExpire <= 0 && record.isBlocked) {
      isBlocked = false;
      blockExpiresAt = null;
      totalHits = 0;
      expiresAt = newExpiresAt;
      await this.prisma.throttlerRecord.update({
        where: { id: record.id },
        data: {
          isBlocked: false,
          blockExpiresAt: null,
          totalHits: 0,
          expiresAt,
        },
      });
    }

    if (!isBlocked) {
      totalHits += 1;
      await this.prisma.throttlerRecord.update({
        where: { id: record.id },
        data: { totalHits },
      });
    }

    if (totalHits > limit && !isBlocked) {
      isBlocked = true;
      blockExpiresAt = new Date(now + blockMs);
      await this.prisma.throttlerRecord.update({
        where: { id: record.id },
        data: { isBlocked: true, blockExpiresAt },
      });
    }

    const finalTimeToExpire = Math.ceil(
      (expiresAt.getTime() - now) / 1000,
    );
    const finalTimeToBlockExpire = blockExpiresAt
      ? Math.ceil((blockExpiresAt.getTime() - now) / 1000)
      : 0;

    return {
      totalHits,
      timeToExpire: Math.max(0, finalTimeToExpire),
      isBlocked,
      timeToBlockExpire: Math.max(0, finalTimeToBlockExpire),
    };
  }
}
