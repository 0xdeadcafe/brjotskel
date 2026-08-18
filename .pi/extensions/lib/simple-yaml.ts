export {};

interface YamlLine {
  indent: number;
  text: string;
  lineNumber: number;
}

interface ParseState {
  lines: YamlLine[];
  index: number;
}

function stripComment(line: string): string {
  let single = false;
  let double = false;
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (double && escaped) {
      escaped = false;
      continue;
    }
    if (double && ch === "\\") {
      escaped = true;
      continue;
    }
    if (!double && ch === "'") {
      single = !single;
      continue;
    }
    if (!single && ch === '"') {
      double = !double;
      continue;
    }
    if (!single && !double && ch === "#" && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i).trimEnd();
    }
  }

  return line.trimEnd();
}

function preprocess(content: string): YamlLine[] {
  const lines: YamlLine[] = [];
  const rawLines = content.replace(/\r\n?/g, "\n").split("\n");

  for (let i = 0; i < rawLines.length; i++) {
    const raw = stripComment(rawLines[i]);
    if (!raw.trim()) continue;
    const indentText = raw.match(/^\s*/)?.[0] || "";
    if (indentText.includes("\t")) {
      throw new Error(`Tabs are not supported for indentation (line ${i + 1}).`);
    }
    lines.push({ indent: indentText.length, text: raw.slice(indentText.length), lineNumber: i + 1 });
  }

  return lines;
}

function isSequenceLine(text: string): boolean {
  return text === "-" || text.startsWith("- ");
}

function findKeySeparator(text: string): number {
  let single = false;
  let double = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (double && escaped) {
      escaped = false;
      continue;
    }
    if (double && ch === "\\") {
      escaped = true;
      continue;
    }
    if (!double && ch === "'") {
      single = !single;
      continue;
    }
    if (!single && ch === '"') {
      double = !double;
      continue;
    }
    if (!single && !double && ch === ":" && (i === text.length - 1 || /\s/.test(text[i + 1]))) {
      return i;
    }
  }

  return -1;
}

function parseKey(rawKey: string, line: YamlLine): string {
  const key = rawKey.trim();
  if (!key) throw new Error(`Missing mapping key on line ${line.lineNumber}.`);
  const parsed = parseScalar(key, line);
  if (typeof parsed !== "string") return String(parsed);
  return parsed;
}

function parseDoubleQuoted(value: string, line: YamlLine): string {
  try {
    return JSON.parse(value);
  } catch (err: any) {
    throw new Error(`Invalid double-quoted string on line ${line.lineNumber}: ${err.message}`);
  }
}

function parseSingleQuoted(value: string, line: YamlLine): string {
  if (!value.endsWith("'")) throw new Error(`Unterminated single-quoted string on line ${line.lineNumber}.`);
  return value.slice(1, -1).replace(/''/g, "'");
}

function isUnterminatedQuotedScalar(value: string): boolean {
  if (value.startsWith("'")) return !value.endsWith("'");
  if (!value.startsWith('"')) return false;

  let escaped = false;
  for (let i = 1; i < value.length; i++) {
    const ch = value[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"' && i === value.length - 1) return false;
  }
  return true;
}

function parseMultilineQuotedScalar(state: ParseState, firstValue: string, line: YamlLine): string {
  const quote = firstValue[0];
  const parts = [firstValue.slice(1)];

  while (state.index < state.lines.length) {
    const next = state.lines[state.index++];
    const text = next.text;
    if (text.endsWith(quote)) {
      parts.push(text.slice(0, -1));
      const joined = parts.join("\n");
      return quote === "'" ? joined.replace(/''/g, "'") : joined;
    }
    parts.push(text);
  }

  throw new Error(`Unterminated quoted string starting on line ${line.lineNumber}.`);
}

function splitFlowItems(value: string, line: YamlLine): string[] {
  const items: string[] = [];
  let single = false;
  let double = false;
  let escaped = false;
  let depth = 0;
  let start = 0;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (double && escaped) {
      escaped = false;
      continue;
    }
    if (double && ch === "\\") {
      escaped = true;
      continue;
    }
    if (!double && ch === "'") {
      single = !single;
      continue;
    }
    if (!single && ch === '"') {
      double = !double;
      continue;
    }
    if (single || double) continue;
    if (ch === "[" || ch === "{") depth++;
    if (ch === "]" || ch === "}") depth--;
    if (depth < 0) throw new Error(`Malformed flow collection on line ${line.lineNumber}.`);
    if (ch === "," && depth === 0) {
      items.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }

  const tail = value.slice(start).trim();
  if (tail) items.push(tail);
  return items;
}

function parseFlowSequence(value: string, line: YamlLine): any[] {
  const inner = value.slice(1, -1).trim();
  return inner === "" ? [] : splitFlowItems(inner, line).map(item => parseScalar(item, line));
}

function parseFlowMapping(value: string, line: YamlLine): Record<string, any> {
  const inner = value.slice(1, -1).trim();
  const out: Record<string, any> = {};
  if (inner === "") return out;

  for (const item of splitFlowItems(inner, line)) {
    const sep = findKeySeparator(item);
    if (sep === -1) throw new Error(`Malformed flow mapping on line ${line.lineNumber}.`);
    out[parseKey(item.slice(0, sep), line)] = parseScalar(item.slice(sep + 1), line);
  }

  return out;
}

function parseScalar(rawValue: string, line: YamlLine): any {
  const value = rawValue.trim();
  if (value === "") return "";
  if (value === "null" || value === "Null" || value === "NULL" || value === "~") return null;
  if (value === "true" || value === "True" || value === "TRUE") return true;
  if (value === "false" || value === "False" || value === "FALSE") return false;
  if (value === "[]") return [];
  if (value === "{}") return {};
  if (value.startsWith("[") && value.endsWith("]")) return parseFlowSequence(value, line);
  if (value.startsWith("{") && value.endsWith("}")) return parseFlowMapping(value, line);
  if (value.startsWith('"')) {
    if (!value.endsWith('"')) throw new Error(`Unterminated double-quoted string on line ${line.lineNumber}.`);
    return parseDoubleQuoted(value, line);
  }
  if (value.startsWith("'")) return parseSingleQuoted(value, line);
  if (/^[+-]?\d+$/.test(value)) return Number.parseInt(value, 10);
  if (/^[+-]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][+-]?\d+)?$/.test(value) || /^[+-]?\d+[eE][+-]?\d+$/.test(value)) {
    return Number.parseFloat(value);
  }
  return value;
}

function parseBlock(state: ParseState, indent: number): any {
  const line = state.lines[state.index];
  if (!line || line.indent < indent) return null;
  if (isSequenceLine(line.text)) return parseSequence(state, indent);
  return parseMapping(state, indent);
}

function parseMappingValue(state: ParseState, parentIndent: number): any {
  const next = state.lines[state.index];
  if (!next) return null;
  if (next.indent > parentIndent || (next.indent === parentIndent && isSequenceLine(next.text))) {
    return parseBlock(state, next.indent);
  }
  return null;
}

function parseMapping(state: ParseState, indent: number): Record<string, any> {
  const out: Record<string, any> = {};

  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line.indent < indent) break;
    if (line.indent > indent) throw new Error(`Unexpected indentation on line ${line.lineNumber}.`);
    if (isSequenceLine(line.text)) break;

    const sep = findKeySeparator(line.text);
    if (sep === -1) throw new Error(`Expected 'key: value' mapping on line ${line.lineNumber}.`);

    const key = parseKey(line.text.slice(0, sep), line);
    const rest = line.text.slice(sep + 1).trim();
    state.index++;
    out[key] = rest === ""
      ? parseMappingValue(state, indent)
      : isUnterminatedQuotedScalar(rest)
        ? parseMultilineQuotedScalar(state, rest, line)
        : parseScalar(rest, line);
  }

  return out;
}

function parseInlineMapItem(rest: string, line: YamlLine): Record<string, any> | null {
  const sep = findKeySeparator(rest);
  if (sep === -1) return null;
  const key = parseKey(rest.slice(0, sep), line);
  const valueText = rest.slice(sep + 1).trim();
  return { [key]: valueText === "" ? null : parseScalar(valueText, line) };
}

function parseSequence(state: ParseState, indent: number): any[] {
  const out: any[] = [];

  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line.indent < indent) break;
    if (line.indent > indent) throw new Error(`Unexpected indentation on line ${line.lineNumber}.`);
    if (!isSequenceLine(line.text)) break;

    const rest = line.text === "-" ? "" : line.text.slice(2).trim();
    state.index++;

    if (rest === "") {
      const next = state.lines[state.index];
      out.push(next && next.indent > indent ? parseBlock(state, next.indent) : null);
      continue;
    }

    const inlineMap = parseInlineMapItem(rest, line);
    if (inlineMap) {
      const next = state.lines[state.index];
      if (next && next.indent > indent) Object.assign(inlineMap, parseMapping(state, next.indent));
      out.push(inlineMap);
      continue;
    }

    out.push(parseScalar(rest, line));
  }

  return out;
}

export function parseYaml(content: string): any {
  const lines = preprocess(content);
  if (lines.length === 0) return {};

  const state: ParseState = { lines, index: 0 };
  const result = parseBlock(state, lines[0].indent);
  if (state.index < lines.length) {
    const line = lines[state.index];
    throw new Error(`Unexpected content on line ${line.lineNumber}.`);
  }
  return result ?? {};
}

function isPlainObject(value: any): value is Record<string, any> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function formatKey(key: string): string {
  return /^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key);
}

function formatScalar(value: any): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : JSON.stringify(String(value));
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value) && value.length === 0) return "[]";
  if (isPlainObject(value) && Object.keys(value).length === 0) return "{}";
  return JSON.stringify(String(value));
}

function dumpBlock(value: any, indent: number): string[] {
  const sp = " ".repeat(indent);

  if (Array.isArray(value)) {
    if (value.length === 0) return [`${sp}[]`];
    const lines: string[] = [];
    for (const item of value) {
      if ((Array.isArray(item) && item.length > 0) || (isPlainObject(item) && Object.keys(item).length > 0)) {
        lines.push(`${sp}-`);
        lines.push(...dumpBlock(item, indent + 2));
      } else {
        lines.push(`${sp}- ${formatScalar(item)}`);
      }
    }
    return lines;
  }

  if (isPlainObject(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return [`${sp}{}`];
    const lines: string[] = [];
    for (const [key, val] of entries) {
      if ((Array.isArray(val) && val.length > 0) || (isPlainObject(val) && Object.keys(val).length > 0)) {
        lines.push(`${sp}${formatKey(key)}:`);
        lines.push(...dumpBlock(val, indent + 2));
      } else {
        lines.push(`${sp}${formatKey(key)}: ${formatScalar(val)}`);
      }
    }
    return lines;
  }

  return [`${sp}${formatScalar(value)}`];
}

export function dumpYaml(value: any): string {
  return `${dumpBlock(value ?? {}, 0).join("\n")}\n`;
}
