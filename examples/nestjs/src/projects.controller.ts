import { Controller, Get, Param, Post, Req } from '@nestjs/common';
import type { Identity } from '@better-iam/core';
import {
  Authorize,
  CurrentIdentity,
  FilterAccessible,
  IamService,
  Public,
  RequireMfa,
  TenantId,
  type RequestLike,
} from '@better-iam/nestjs';
import { demo } from './demo.js';

const projects = ['apollo', 'gemini', 'mercury'].map((id) => ({
  id,
  name: id[0]!.toUpperCase() + id.slice(1),
}));

@Controller()
export class ProjectsController {
  constructor(private readonly iam: IamService) {}

  /** Public: tells the smoke test (and a login page) which tenant to sign in to. */
  @Public()
  @Get('status')
  async status() {
    return { tenantId: demo.tenantId ?? null, iam: await this.iam.health() };
  }

  @Get('me')
  async me(@CurrentIdentity() identity: Identity, @Req() request: RequestLike) {
    const flags = await this.iam.can(request, {
      tenantId: identity.tenantId,
      checks: [{ action: 'iam:identities:read' }],
    });
    return {
      id: identity.id,
      email: identity.email,
      canReadMembers: flags[`iam:identities:read@iam/${identity.tenantId}`] ?? false,
    };
  }

  /** Every project the application knows about, trimmed to what the caller may read. */
  @Get('projects')
  @FilterAccessible('projects:read', { type: 'project' })
  list() {
    return projects;
  }

  @Get('projects/:id')
  @Authorize('projects:read', { resource: { type: 'project', id: { param: 'id' } } })
  read(@Param('id') id: string, @TenantId() tenantId: string) {
    return { ...projects.find((project) => project.id === id), tenantId };
  }

  @Post('projects/:id/archive')
  @RequireMfa()
  @Authorize('projects:manage', { resource: { type: 'project', id: { param: 'id' } } })
  archive(@Param('id') id: string) {
    return { archived: id };
  }
}
