import { Injectable, Logger } from '@nestjs/common';
import type { AuditEvent } from '@better-iam/core';
import { OnIamEvent } from '@better-iam/nestjs';
import { demo } from './demo.js';

/** Reacts to audit events after they commit; delivery is at least once. */
@Injectable()
export class AuditListener {
  private readonly logger = new Logger('Audit');

  @OnIamEvent(['auth:*', 'iam:*'])
  record(event: AuditEvent) {
    demo.events.push(`${event.action}:${event.outcome}`);
    this.logger.log(`${event.action} ${event.outcome} by ${event.actorId}`);
  }
}
