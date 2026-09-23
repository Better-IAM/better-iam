import { iamNext } from '@/lib/iam';

export const runtime = 'nodejs';
export const { GET, POST, OPTIONS } = iamNext.handlers();
