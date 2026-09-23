import { redirect } from 'react-router';
import { iamRouter } from '../iam.server';
import type { Route } from './+types/logout';

export async function action(args: Route.ActionArgs) {
  await iamRouter.helpers(args).signOut();
  throw redirect('/');
}
