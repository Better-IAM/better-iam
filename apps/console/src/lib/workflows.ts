/** Labels shared by the console's workflow pages. */

type Trigger =
  | { kind: 'joiner' }
  | { kind: 'mover'; attributes: string[] }
  | { kind: 'leaver' }
  | { kind: 'date'; attribute: string; offsetDays: number }
  | { kind: 'manual' };

export const triggerOptions = [
  { value: 'joiner', label: 'Joiner: someone joins' },
  { value: 'mover', label: 'Mover: an attribute changes' },
  { value: 'leaver', label: 'Leaver: someone is disabled' },
  { value: 'date', label: 'Date: before or after a date they carry' },
  { value: 'manual', label: 'Manual: only when you run it' },
];

export function describeTrigger(trigger: Trigger): string {
  switch (trigger.kind) {
    case 'joiner':
      return 'When someone joins';
    case 'mover':
      return `When ${trigger.attributes.join(', ')} changes`;
    case 'leaver':
      return 'When someone is disabled';
    case 'date': {
      const days = Math.abs(trigger.offsetDays);
      return trigger.offsetDays === 0
        ? `On ${trigger.attribute}`
        : `${days} day${days === 1 ? '' : 's'} ${trigger.offsetDays < 0 ? 'before' : 'after'} ${trigger.attribute}`;
    }
    case 'manual':
      return 'When run by hand';
  }
}

export function stepSummary(step: { kind: string; hours?: number; name?: string; to?: string }): string {
  if (step.kind === 'wait' && step.hours)
    return step.hours % 24 === 0 ? `wait ${step.hours / 24}d` : `wait ${step.hours}h`;
  if (step.kind === 'emit-event' && step.name) return `event ${step.name}`;
  if (step.kind === 'send-email' && step.to) return `email ${step.to}`;
  return step.kind;
}
