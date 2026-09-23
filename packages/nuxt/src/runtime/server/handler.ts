import { defineEventHandler } from '#imports';
import { iamH3 } from './state.js';

/** Mounted at `${apiPath}/**`: the IAM HTTP API, protocol endpoints, health, and metrics. */
export default defineEventHandler((event) => iamH3.handler(event));
