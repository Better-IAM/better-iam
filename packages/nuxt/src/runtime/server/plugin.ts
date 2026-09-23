import { defineNitroPlugin } from '#imports';
import { iamH3 } from './state.js';

/** Binds an in-process session client to every request so server rendering reads the session without HTTP. */
export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook('request', (event) => {
    event.context.betterIam = iamH3.bind(event);
  });
});
