import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const serverRoot = new URL("../", import.meta.url);
const appDocsRoot = new URL("../../lunari_app/docs/launch/", import.meta.url);

const pages = [
  {
    name: "privacy",
    source: new URL("privacy_policy_ko.md", appDocsRoot),
    html: new URL("public/privacy.html", serverRoot),
    title: "LUNARI 개인정보처리방침",
    reciprocalLink: 'href="/terms"',
  },
  {
    name: "terms",
    source: new URL("terms_of_service_ko.md", appDocsRoot),
    html: new URL("public/terms.html", serverRoot),
    title: "LUNARI 이용약관",
    reciprocalLink: 'href="/privacy"',
  },
];

function visibleMarkdownLines(markdown) {
  return markdown
    .split(/\r?\n/)
    .map((line) =>
      line
        .replace(/^#{1,6}\s+/, "")
        .replace(/^>\s?/, "")
        .replace(/^[-*]\s+/, "")
        .replaceAll("`", "")
        .trim(),
    )
    .filter(Boolean);
}

for (const page of pages) {
  test(`${page.name} page contains the complete Korean source`, async () => {
    const [source, html] = await Promise.all([
      readFile(page.source, "utf8"),
      readFile(page.html, "utf8"),
    ]);

    assert.match(html, /<meta charset="utf-8">/i);
    assert.ok(html.includes(`<title>${page.title}</title>`));
    assert.ok(html.includes(page.reciprocalLink));
    const visibleHtml = html.replace(/<[^>]+>/g, "");
    for (const line of visibleMarkdownLines(source)) {
      assert.ok(visibleHtml.includes(line), `Missing source text: ${line}`);
    }
  });
}

test("legal pages expose no credential-shaped values", async () => {
  const html = (
    await Promise.all(pages.map((page) => readFile(page.html, "utf8")))
  ).join("\n");

  assert.doesNotMatch(html, /-----BEGIN (?:RSA )?PRIVATE KEY-----/);
  assert.doesNotMatch(html, /postgres(?:ql)?:\/\/[^\s<]+/i);
  assert.doesNotMatch(html, /sk-[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(html, /ca-app-pub-\d{16}[~/]\d{10}/);
});

test("Vercel clean URLs expose /privacy and /terms without rewrites", async () => {
  const config = JSON.parse(
    await readFile(new URL("vercel.json", serverRoot), "utf8"),
  );
  assert.equal(config.cleanUrls, true);
  assert.equal(config.rewrites, undefined);
});
