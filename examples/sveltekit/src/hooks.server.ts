import type { Handle, ServerInit } from '@sveltejs/kit';
import { iamKit, seed } from '$lib/server/iam';

export const init: ServerInit = seed;

export const handle: Handle = iamKit.handle;
