import { iso } from "./utils";

export interface ParsedFeedItem {
  id: string;
  title: string;
  link: string;
  description?: string;
  publishedAt?: string;
  updatedAt?: string;
}

/** Minimal, dependency-free RSS/Atom reader for trusted vendor discovery feeds. */
export function parseVendorFeed(xml: string): ParsedFeedItem[] {
  const blocks = [
    ...xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi),
    ...xml.matchAll(/<entry(?:\s[^>]*)?>([\s\S]*?)<\/entry>/gi),
  ].map((match) => match[1]);

  return blocks.slice(0, 2_000).flatMap((block) => {
    const title = textElement(block, "title");
    const link = rssLink(block);
    const id = textElement(block, "guid") ?? textElement(block, "id") ?? link;
    if (!title || !link || !id) return [];
    return [{
      id,
      title,
      link,
      description: textElement(block, "content:encoded") ?? textElement(block, "description") ?? textElement(block, "summary") ?? textElement(block, "content"),
      publishedAt: iso(textElement(block, "pubDate") ?? textElement(block, "published")),
      updatedAt: iso(textElement(block, "updated")),
    } satisfies ParsedFeedItem];
  });
}

export function feedItemInWindow(item: ParsedFeedItem, since?: string, until?: string): boolean {
  const timestamp = item.updatedAt ?? item.publishedAt;
  if (!timestamp) return true;
  const value = new Date(timestamp).getTime();
  const lower = since ? new Date(since).getTime() : Number.NEGATIVE_INFINITY;
  const upper = until ? new Date(until).getTime() : Number.POSITIVE_INFINITY;
  return value >= lower && value <= upper;
}

function rssLink(block: string): string | undefined {
  const element = block.match(/<link(?:\s[^>]*)?>([\s\S]*?)<\/link>/i);
  if (element) return decodeXml(unwrapCdata(element[1])).trim() || undefined;
  const atom = block.match(/<link\b([^>]*)\/?\s*>/i);
  const href = atom?.[1].match(/\bhref=["']([^"']+)["']/i)?.[1];
  return href ? decodeXml(href).trim() : undefined;
}

function textElement(block: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = block.match(new RegExp(`<${escaped}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${escaped}>`, "i"));
  const value = match ? decodeXml(unwrapCdata(match[1])).trim() : "";
  return value || undefined;
}

function unwrapCdata(value: string): string {
  const match = value.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/i);
  return match?.[1] ?? value;
}

function decodeXml(value: string): string {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal: string) => String.fromCodePoint(Number.parseInt(decimal, 10)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}
