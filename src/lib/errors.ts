export const describeError = (value: unknown): string => {
  if (value instanceof Error) {
    return value.message;
  }
  if (typeof value === "string") {
    return value;
  }
  if (value === undefined) {
    return "undefined";
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value.toString();
  }
  if (typeof value === "symbol") {
    return value.toString();
  }
  try {
    const json = JSON.stringify(value);
    if (typeof json === "string") {
      return json;
    }
  } catch {
    return "[unserialisable error]";
  }
  return "[unserialisable error]";
};
