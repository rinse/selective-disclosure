// Fetch the last element of a union type
type LastOfUnion<U> = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (U extends any ? (k: U[]) => void : never) extends (k: infer I1) => void
    ? I1
    : never
) extends (infer I2)[]
  ? I2
  : never;

// Returns true if the given type is never.
type IsNever<T> = T[] extends never[] ? true : false;

// Returns true if the given type is a union type.
export type IsUnion<T> = IsNever<Exclude<T, LastOfUnion<T>>> extends true
  ? false
  : true;

// stringify with fancy spaces for testing purposes.
// Examples in the specification has this kind of format.
export function fancyStringify(value: unknown): string {
    return JSON.stringify(value).replaceAll(",", ", ").replaceAll(":", ": ");
}
