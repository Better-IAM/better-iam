// Pure helpers behind ApiForm (components/api-form.tsx): field defaults and the JSON body built from a submitted form.

export interface FieldOption {
  value: string;
  label: string;
}
export interface FieldSpec {
  name: string;
  label: string;
  type?:
    | 'text'
    | 'email'
    | 'password'
    | 'textarea'
    | 'json'
    | 'list'
    | 'number'
    | 'checkbox'
    | 'select'
    | 'multiselect'
    | 'datetime'
    | 'hidden';
  placeholder?: string;
  required?: boolean;
  /**
   * The initial value. Multiselects take the values to preselect, so a form that replaces a whole record keeps the
   * current selection. Datetime fields take an epoch in milliseconds, shown in the browser's time zone (a string
   * formatted on the server would be read back in a different zone).
   */
  defaultValue?: string | boolean | number | string[];
  /** An empty field is sent as JSON `null` instead of being left out, for inputs where `null` clears a value. */
  emptyAsNull?: boolean;
  options?: FieldOption[];
  help?: string;
  rows?: number;
  /** Nests the value under this object key in the request body, for inputs such as `{ authPolicy: { requireMfa } }`. */
  group?: string;
  /** Number fields: the entered value is multiplied before sending (minutes entered, milliseconds sent). */
  multiplier?: number;
}

/** What `bodyFrom` reads from a form; `FormData` satisfies it. */
export interface FormValues {
  get(name: string): FormDataEntryValue | null;
  getAll(name: string): FormDataEntryValue[];
}

/** An epoch as a `datetime-local` value in this runtime's time zone, to the minute. Call it in the browser. */
export function dateTimeLocalValue(epoch: number): string {
  const date = new Date(epoch);
  const pad = (part: number) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** The `defaultValue` of a select: the preselected values of a multiselect, one value otherwise. */
export function selectDefault(field: FieldSpec): string | string[] {
  const value = field.defaultValue;
  if (field.type === 'multiselect')
    return Array.isArray(value)
      ? value
      : value === undefined || value === ''
        ? []
        : [String(value)];
  return Array.isArray(value) ? (value[0] ?? '') : String(value ?? '');
}

/** The `defaultValue` of a text-like input. Lists join an array default; datetime epochs are filled in after mount. */
export function textDefault(field: FieldSpec): string {
  const value = field.defaultValue;
  if (Array.isArray(value)) return value.join(', ');
  if (field.type === 'datetime' && typeof value === 'number') return '';
  return String(value ?? '');
}

/** Builds a JSON request body from declarative fields so server components can describe forms without passing functions. */
export function bodyFrom(data: FormValues, fields: FieldSpec[]): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = data.get(field.name);
    const value = typeof raw === 'string' ? raw : '';
    const body = field.group ? ((root[field.group] ??= {}) as Record<string, unknown>) : root;
    const empty = () => {
      if (field.emptyAsNull) body[field.name] = null;
    };
    switch (field.type) {
      case 'checkbox':
        body[field.name] = data.get(field.name) === 'on';
        break;
      case 'number':
        if (value.trim()) body[field.name] = Number(value) * (field.multiplier ?? 1);
        else empty();
        break;
      case 'datetime': {
        if (!value.trim()) {
          empty();
          break;
        }
        // An untouched pre-filled field sends the stored instant itself: the input shows only minutes, so reading it
        // back would drop the seconds and move the value on every save.
        if (
          typeof field.defaultValue === 'number' &&
          value === dateTimeLocalValue(field.defaultValue)
        ) {
          body[field.name] = field.defaultValue;
          break;
        }
        // `datetime-local` values carry no offset; the browser reads them in its own zone, where they were shown.
        const time = new Date(value).getTime();
        if (!Number.isFinite(time)) throw new Error(`${field.label} must be a date and time`);
        body[field.name] = time;
        break;
      }
      case 'json':
        if (value.trim()) {
          try {
            body[field.name] = JSON.parse(value);
          } catch {
            throw new Error(`${field.label} must be valid JSON`);
          }
        } else empty();
        break;
      case 'list': {
        const items = value
          .split(',')
          .map((item) => item.trim())
          .filter(Boolean);
        if (items.length || field.required) body[field.name] = items;
        else empty();
        break;
      }
      case 'multiselect': {
        const items = data
          .getAll(field.name)
          .filter((item): item is string => typeof item === 'string' && item !== '');
        if (items.length) body[field.name] = items;
        else empty();
        break;
      }
      default:
        if (value !== '' || field.required) body[field.name] = value;
        else empty();
    }
  }
  return root;
}
