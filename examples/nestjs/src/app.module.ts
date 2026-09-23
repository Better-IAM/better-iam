import { Controller, Get, Module } from '@nestjs/common';
import { IamModule, Public } from '@better-iam/nestjs';
import { AuditListener } from './audit.listener.js';
import { demo } from './demo.js';
import { iam } from './iam.js';
import { ProjectsController } from './projects.controller.js';

@Controller('events')
class EventsController {
  /** Demo only: what the audit listener has seen, so the smoke test can check event delivery. */
  @Public()
  @Get()
  list() {
    return demo.events;
  }
}

@Module({
  imports: [
    IamModule.forRoot({
      iam,
      guard: true, // every route needs a session unless @Public()
      mount: true, // POST /api/iam/* (sign-in, MFA, admin API) and GET /api/iam/health
      dispatchIntervalMs: 200, // deliver audit events to @OnIamEvent handlers
    }),
  ],
  controllers: [ProjectsController, EventsController],
  providers: [AuditListener],
})
export class AppModule {}
