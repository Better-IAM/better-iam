import { iamRouter } from '../iam.server';

// The IAM HTTP API for the browser client: GET routes (health) and POST routes (every method).
export const loader = iamRouter.api;
export const action = iamRouter.api;
