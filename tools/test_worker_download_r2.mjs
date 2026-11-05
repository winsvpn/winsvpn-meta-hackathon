// R2-hosted website download route in web/_worker.js (owner ruling 2026-10-25).
// Run: "$WINS_RELEASE_NODE" tools/test_worker_download_r2.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

// Workers ships crypto.DigestStream; Node does not. This stand-in has the same
// contract: a WritableStream whose .digest promise resolves to an ArrayBuffer.
class NodeDigestStream extends WritableStream {
  constructor(algorithm) {
    assert.equal(algorithm, "SHA-256");
    const hash = createHash("sha256");
    let resolveDigest;
    let rejectDigest;
    const digest = new Promise((resolve, reject) => {
      resolveDigest = resolve;
      rejectDigest = reject;
    });
    super({
      write(chunk) { hash.update(chunk); },
      close() {
        const out = hash.digest();
        resolveDigest(out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength));
      },
      abort(reason) { rejectDigest(reason); },
    });
    this.digest = digest;
  }
}
globalThis.crypto.DigestStream = NodeDigestStream;

const source = await readFile(new URL("../web/_worker.js", import.meta.url), "utf8");
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const worker = await import(moduleUrl);

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const LINUX = "wins-vpn-linux-x64.tar.gz";
const WINDOWS_UNSIGNED = "WinsVPN-UNSIGNED-LOCAL-Setup.exe";
const linuxBytes = new Uint8Array(200_000).map((_, index) => (index * 31) % 251);
const windowsBytes = new Uint8Array(150_000).map((_, index) => (index * 7) % 253);
const linuxSha = sha256Hex(linuxBytes);
const windowsSha = sha256Hex(windowsBytes);
const waiverBytes = new TextEncoder().encode('{"public_label":"Unsigned"}\n');
const waiverSha = sha256Hex(waiverBytes);
const emptyReceiptSha = sha256Hex(new TextEncoder().encode("{}"));

function receipts(filename) {
  return Object.fromEntries(
    [["winn_provenance", "winn"], ["privacy", "privacy"], ["release_receipt", "release"], ["publication_receipt", "publication"]]
      .map(([key, suffix]) => [key, { receipt_filename: `${filename}.${suffix}.json`, receipt_sha256: "b".repeat(64) }])
  );
}

function manifest({ windowsArtifact = {}, schema = "winsvpn-download-manifest-v2" } = {}) {
  return {
    schema,
    release_id: "v1.0.16+33",
    artifacts: [
      {
        id: "windows-x64",
        status: "available",
        delivery: { kind: "direct", url: `https://winsvpn.org/downloads/${WINDOWS_UNSIGNED}` },
        artifact: {
          filename: WINDOWS_UNSIGNED,
          sha256: windowsSha,
          bytes: windowsBytes.byteLength,
          signature: { kind: "unsigned_owner_waiver", sha256: waiverSha },
          unsigned_waiver: { label: "Unsigned", waiver_filename: "download-unsigned-waiver.json", waiver_sha256: waiverSha },
          ...receipts(WINDOWS_UNSIGNED),
          ...windowsArtifact,
        },
      },
      { id: "android", status: "verification_pending", delivery: { kind: "direct", url: null }, artifact: { filename: null, sha256: null, bytes: null } },
      {
        id: "linux-x64",
        status: "available",
        delivery: { kind: "direct", url: `https://winsvpn.org/downloads/${LINUX}` },
        artifact: {
          filename: LINUX,
          sha256: linuxSha,
          bytes: linuxBytes.byteLength,
          signature: { kind: "publication_signature_sha256", sha256: "c".repeat(64) },
          ...receipts(LINUX),
        },
      },
      { id: "macos", status: "store_pending", delivery: { kind: "store", url: null }, artifact: { filename: null, sha256: null, bytes: null } },
    ],
  };
}

function chunked(bytes, size = 16_384) {
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.byteLength) { controller.close(); return; }
      controller.enqueue(bytes.slice(offset, offset + size));
      offset += size;
    },
  });
}

function bucket(objects, { calls = [], checksum = {} } = {}) {
  const lookup = (key) => {
    const bytes = objects.get(key);
    if (!bytes) return null;
    return { key, size: bytes.byteLength, checksums: checksum[key] ? { sha256: checksum[key] } : {} };
  };
  return {
    calls,
    async head(key) { calls.push(["head", key]); return lookup(key); },
    async get(key) {
      calls.push(["get", key]);
      const meta = lookup(key);
      return meta ? { ...meta, body: chunked(objects.get(key)) } : null;
    },
  };
}

function env({ manifestPayload = manifest(), manifestStatus = 200, objects, calls, checksum, assets = {} } = {}) {
  const store = objects || new Map([
    [`downloads/sha256/${linuxSha}`, linuxBytes],
    [`downloads/sha256/${windowsSha}`, windowsBytes],
  ]);
  return {
    ASSETS: {
      async fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === "/releases/downloads.json") {
          return new Response(JSON.stringify(manifestPayload), {
            status: manifestStatus,
            headers: { "content-type": "application/json" },
          });
        }
        if (assets[path]) return assets[path]();
        if (path === "/releases/download-unsigned-waiver.json") {
          return new Response(waiverBytes, { headers: { "content-type": "application/json" } });
        }
        return new Response("<html>home</html>", { status: 200, headers: { "content-type": "text/html" } });
      },
    },
    DOWNLOADS_BUCKET: bucket(store, { calls, checksum }),
  };
}

async function get(path, environment, init = {}) {
  return worker.default.fetch(new Request(`https://winsvpn.org${path}`, init), environment, {});
}

async function readAll(response) {
  const reader = response.body.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const step = await reader.read();
    if (step.done) break;
    parts.push(step.value);
    total += step.value.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.byteLength; }
  return out;
}

let cases = 0;
const failed = [];
async function check(name, fn) {
  try {
    await fn();
  } catch (error) {
    failed.push(name);
    process.stdout.write(`not ok ${name}: ${String(error && error.message).split("\n")[0]}\n`);
    return;
  }
  cases += 1;
  process.stdout.write(`ok ${name}\n`);
}

await check("key is content-addressed and derived only from the manifest SHA-256", async () => {
  assert.equal(worker.downloadR2ObjectKey(linuxSha), `downloads/sha256/${linuxSha}`);
  assert.equal(worker.downloadR2ObjectKey("../etc/passwd"), null);
  const bindings = worker.downloadManifestBindings(manifest());
  assert.deepEqual(bindings.get(`/downloads/${LINUX}`), {
    source: "r2", key: `downloads/sha256/${linuxSha}`, sha256: linuxSha, bytes: linuxBytes.byteLength, filename: LINUX, waiverSha256: null,
  });
  assert.equal(bindings.get(`/downloads/${LINUX}.sigstore.json`).source, "assets");
  assert.equal(bindings.get(`/downloads/${WINDOWS_UNSIGNED}.privacy.json`).source, "assets");
});

await check("verified linux artifact streams exact bytes from R2", async () => {
  const calls = [];
  const response = await get(`/downloads/${LINUX}`, env({ calls }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-wins-download-route"), "r2-verified");
  assert.equal(response.headers.get("content-type"), "application/octet-stream");
  assert.equal(response.headers.get("accept-ranges"), "none");
  assert.equal(response.headers.get("x-wins-download-sha256"), linuxSha);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(await readAll(response), linuxBytes);
  assert.deepEqual(calls, [["get", `downloads/sha256/${linuxSha}`]]);
});

await check("owner-waived unsigned Windows artifact is served with its exact bytes", async () => {
  const response = await get(`/downloads/${WINDOWS_UNSIGNED}`, env());
  assert.equal(response.status, 200);
  assert.deepEqual(await readAll(response), windowsBytes);
});

await check("tampered R2 bytes of the right size never complete", async () => {
  const tampered = linuxBytes.slice();
  tampered[tampered.length - 1] ^= 0xff;
  const objects = new Map([[`downloads/sha256/${linuxSha}`, tampered]]);
  const response = await get(`/downloads/${LINUX}`, env({ objects }));
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  let received = 0;
  await assert.rejects(async () => {
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      received += step.value.byteLength;
    }
  }, /does not match the manifest SHA-256/);
  assert.ok(received < linuxBytes.byteLength, `received ${received} of ${linuxBytes.byteLength}`);
});

await check("R2 object with a different size is refused before streaming", async () => {
  const objects = new Map([[`downloads/sha256/${linuxSha}`, linuxBytes.slice(1)]]);
  const response = await get(`/downloads/${LINUX}`, env({ objects }));
  assert.equal(response.status, 404);
  assert.equal(response.headers.get("x-wins-download-route"), "r2-mismatch");
});

await check("R2 SHA-256 checksum that disagrees with the manifest is refused", async () => {
  const wrong = new Uint8Array(32).fill(9).buffer;
  const response = await get(`/downloads/${LINUX}`, env({ checksum: { [`downloads/sha256/${linuxSha}`]: wrong } }));
  assert.equal(response.status, 404);
});

await check("missing R2 object and missing binding fail closed", async () => {
  assert.equal((await get(`/downloads/${LINUX}`, env({ objects: new Map() }))).status, 404);
  const noBucket = env();
  delete noBucket.DOWNLOADS_BUCKET;
  const response = await get(`/downloads/${LINUX}`, noBucket);
  assert.equal(response.status, 404);
  assert.equal(response.headers.get("x-wins-download-route"), "r2-unavailable");
});

await check("unknown, pending and v1-schema paths never reach R2", async () => {
  const calls = [];
  assert.equal((await get("/downloads/wins-vpn-android.apk", env({ calls }))).status, 404);
  assert.equal((await get("/downloads/WinsVPN-Setup.exe", env({ calls }))).status, 404);
  assert.equal((await get(`/downloads/${LINUX}`, env({ calls, manifestPayload: manifest({ schema: "winsvpn-download-manifest-v1" }) }))).status, 404);
  assert.equal((await get(`/downloads/${LINUX}`, env({ calls, manifestStatus: 404 }))).status, 404);
  assert.deepEqual(calls, []);
});

await check("unsigned Windows without the Unsigned waiver label is not authorized", async () => {
  const calls = [];
  const noLabel = manifest({ windowsArtifact: { unsigned_waiver: { label: "", waiver_filename: "download-unsigned-waiver.json", waiver_sha256: waiverSha } } });
  assert.equal((await get(`/downloads/${WINDOWS_UNSIGNED}`, env({ calls, manifestPayload: noLabel }))).status, 404);
  const mismatched = manifest({ windowsArtifact: { unsigned_waiver: { label: "Unsigned", waiver_filename: "download-unsigned-waiver.json", waiver_sha256: "f".repeat(64) } } });
  assert.equal((await get(`/downloads/${WINDOWS_UNSIGNED}`, env({ calls, manifestPayload: mismatched }))).status, 404);
  const renamed = manifest({ windowsArtifact: { filename: "WinsVPN-Setup.exe" } });
  renamed.artifacts[0].delivery.url = "https://winsvpn.org/downloads/WinsVPN-Setup.exe";
  assert.equal((await get("/downloads/WinsVPN-Setup.exe", env({ calls, manifestPayload: renamed }))).status, 404);
  assert.deepEqual(calls, []);
});

await check("HEAD answers from R2 metadata without a body; POST is refused", async () => {
  const head = await get(`/downloads/${LINUX}`, env(), { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-length"), String(linuxBytes.byteLength));
  const post = await get(`/downloads/${LINUX}`, env(), { method: "POST", body: "x" });
  assert.equal(post.status, 405);
});

await check("Range requests still return the whole verified object", async () => {
  const response = await get(`/downloads/${LINUX}`, env(), { headers: { Range: "bytes=0-9" } });
  assert.equal(response.status, 200);
  assert.equal((await readAll(response)).byteLength, linuxBytes.byteLength);
});

await check("Pages receipts must match the deployed manifest digest (DLP-02)", async () => {
  const receiptPath = `/downloads/${LINUX}.release.json`;
  const payload = manifest();
  payload.artifacts[2].artifact.release_receipt.receipt_sha256 = emptyReceiptSha;
  const json = (text) => () => new Response(text, { headers: { "content-type": "application/json" } });
  const ok = await get(receiptPath, env({ manifestPayload: payload, assets: { [receiptPath]: json("{}") } }));
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("x-wins-download-route"), "static-asset");
  assert.equal(await ok.text(), "{}");
  const tampered = await get(receiptPath, env({ manifestPayload: payload, assets: { [receiptPath]: json("[]") } }));
  assert.equal(tampered.status, 404);
  const ranged = await get(receiptPath, env({ manifestPayload: payload, assets: { [receiptPath]: json("{}") } }), { headers: { Range: "bytes=0-0" } });
  assert.equal(ranged.status, 200);
  assert.equal(await ranged.text(), "{}");
  const post = await get(receiptPath, env({ manifestPayload: payload, assets: { [receiptPath]: json("{}") } }), { method: "POST", body: "x" });
  assert.equal(post.status, 405);
  assert.equal((await get(receiptPath, env({ manifestPayload: payload }))).status, 404);
  const sidecarPath = `/downloads/${LINUX}.sha256`;
  const sidecar = (text) => ({ [sidecarPath]: () => new Response(text, { headers: { "content-type": "text/plain" } }) });
  assert.equal((await get(sidecarPath, env({ assets: sidecar(`${linuxSha}  ${LINUX}\n`) }))).status, 200);
  assert.equal((await get(sidecarPath, env({ assets: sidecar(`${"0".repeat(64)}  ${LINUX}\n`) }))).status, 404);
});

await check("missing or altered public unsigned waiver blocks Windows bytes (DLP-02)", async () => {
  const missing = await get(`/downloads/${WINDOWS_UNSIGNED}`, env({
    assets: { "/releases/download-unsigned-waiver.json": () => new Response("Not Found", { status: 404 }) },
  }));
  assert.equal(missing.status, 404);
  const altered = await get(`/downloads/${WINDOWS_UNSIGNED}`, env({
    assets: { "/releases/download-unsigned-waiver.json": () => new Response("{}", { headers: { "content-type": "application/json" } }) },
  }));
  assert.equal(altered.status, 404);
  assert.equal(altered.headers.get("x-wins-download-route"), "waiver-mismatch");
});

await check("reused source buffer cannot change bytes after hashing (DLP-01)", async () => {
  const payload = manifest();
  const expected = new Uint8Array([65, 65, 66, 66]);
  const sha = sha256Hex(expected);
  payload.artifacts[2].artifact.sha256 = sha;
  payload.artifacts[2].artifact.bytes = expected.byteLength;
  const shared = new Uint8Array([65, 65]);
  const body = new ReadableStream({ start(controller) {
    controller.enqueue(shared);
    setTimeout(() => { shared.set([66, 66]); controller.enqueue(shared); controller.close(); }, 30);
  } });
  const environment = env({ manifestPayload: payload });
  environment.DOWNLOADS_BUCKET = {
    async head(key) { return { key, size: expected.byteLength, checksums: {} }; },
    async get(key) { return { key, size: expected.byteLength, checksums: {}, body }; },
  };
  const response = await get(`/downloads/${LINUX}`, environment);
  assert.deepEqual(await readAll(response), expected);
});

await check("signed Windows names and Android are outside this release ruling (DLP-05)", async () => {
  const payload = manifest();
  const entry = payload.artifacts[0];
  entry.artifact.filename = "WinsVPN-Setup.exe";
  entry.artifact.signature = { kind: "authenticode_signer_certificate_sha256", sha256: "d".repeat(64) };
  delete entry.artifact.unsigned_waiver;
  entry.artifact.windows_verification = { receipt_filename: "WinsVPN-Setup.exe.authenticode.json", receipt_sha256: "d".repeat(64) };
  Object.assign(entry.artifact, receipts("WinsVPN-Setup.exe"));
  entry.delivery.url = "https://winsvpn.org/downloads/WinsVPN-Setup.exe";
  assert.equal(worker.downloadManifestBoundPaths(payload).has("/downloads/WinsVPN-Setup.exe"), false);
  const android = manifest();
  android.artifacts[1] = {
    id: "android",
    status: "available",
    delivery: { kind: "direct", url: "https://winsvpn.org/downloads/wins-vpn-android.apk" },
    artifact: { filename: "wins-vpn-android.apk", sha256: "a".repeat(64), bytes: 1, signature: { kind: "apk_signer_certificate_sha256", sha256: "4".repeat(64) }, ...receipts("wins-vpn-android.apk") },
  };
  assert.equal(worker.downloadManifestBoundPaths(android).has("/downloads/wins-vpn-android.apk"), false);
});

await check("pinned GitHub entries expose only their Pages receipts, never a redirect", async () => {
  const pinned = `https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/${LINUX}`;
  const payload = manifest();
  payload.artifacts[2].delivery = { kind: "github_release", url: pinned };
  payload.artifacts[2].artifact.release_receipt.receipt_sha256 = emptyReceiptSha;
  const calls = [];
  const receiptPath = `/downloads/${LINUX}.release.json`;
  const assets = { [receiptPath]: () => new Response("{}", { headers: { "content-type": "application/json" } }) };
  const bindings = worker.downloadManifestBindings(payload);
  assert.equal(bindings.has(`/downloads/${LINUX}`), false);
  assert.equal(bindings.get(receiptPath).source, "assets");
  const binary = await get(`/downloads/${LINUX}`, env({ calls, manifestPayload: payload, assets }));
  assert.equal(binary.status, 404);
  assert.equal(binary.headers.get("location"), null);
  assert.equal((await get(receiptPath, env({ calls, manifestPayload: payload, assets }))).status, 200);
  for (const url of [
    pinned.replace("v1.0.16-33", "v1.0.0"),
    pinned.replace("v1.0.16-33", "v1.0.16+33"),
    pinned.replace("https://github.com", "https://github.com.evil.example"),
    `${pinned}?x=1`,
  ]) {
    const other = manifest();
    other.artifacts[2].delivery = { kind: "github_release", url };
    assert.equal(worker.downloadManifestBindings(other).has(receiptPath), false, url);
  }
  const android = manifest();
  android.artifacts[1] = {
    id: "android",
    status: "available",
    delivery: { kind: "github_release", url: "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/wins-vpn-android.apk" },
    artifact: { filename: "wins-vpn-android.apk", sha256: "a".repeat(64), bytes: 1, signature: { kind: "apk_signer_certificate_sha256", sha256: "4".repeat(64) }, ...receipts("wins-vpn-android.apk") },
  };
  assert.equal(worker.downloadManifestBindings(android).has("/downloads/wins-vpn-android.apk.release.json"), false);
  assert.deepEqual(calls, []);
});

await check("empty trailing chunk cannot flush the withheld final chunk early (Argon F-1)", async () => {
  const corrupt = new Uint8Array(linuxBytes);
  corrupt[corrupt.length - 1] ^= 0xff;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(corrupt.slice(0, 64));
      controller.enqueue(corrupt.slice(64));
      controller.enqueue(new Uint8Array(0));
      controller.close();
    },
  });
  const environment = env();
  environment.DOWNLOADS_BUCKET = {
    async head() { return null; },
    async get(key) { return { key, size: linuxBytes.byteLength, checksums: {}, body }; },
  };
  const response = await get(`/downloads/${LINUX}`, environment);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-length"), String(linuxBytes.byteLength));
  const reader = response.body.getReader();
  let received = 0;
  await assert.rejects(async () => {
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      received += step.value.byteLength;
    }
  }, /manifest SHA-256/);
  assert.ok(received < linuxBytes.byteLength, `received ${received}`);
});

await check("receipt name collision or wrong signature kind is not authorized (Argon F-3)", async () => {
  const collided = manifest();
  collided.artifacts[2].artifact.release_receipt.receipt_filename = LINUX;
  assert.equal((await get(`/downloads/${LINUX}`, env({ manifestPayload: collided }))).status, 404);
  const badKind = manifest();
  badKind.artifacts[2].artifact.signature.kind = "unsigned_owner_waiver";
  assert.equal((await get(`/downloads/${LINUX}`, env({ manifestPayload: badKind }))).status, 404);
  const unkeyed = manifest();
  unkeyed.artifacts[2].artifact.signature.sha256 = linuxSha;
  assert.equal((await get(`/downloads/${LINUX}`, env({ manifestPayload: unkeyed }))).status, 404);
});

await check("local custody records are blocked at the Worker edge (Argon F-4)", async () => {
  for (const blockedPath of [
    "/i18n/major.json",
    "/releases/owner-publication-evidence.json",
    "/releases/download-custody-challenge.json",
    "/releases/download-custody-consumed.jsonl",
    "/releases/README.md",
  ]) {
    const response = await get(blockedPath, env({ assets: { [blockedPath]: () => new Response("{}", { headers: { "content-type": "application/json" } }) } }));
    assert.equal(response.status, 404, blockedPath);
  }
});

if (failed.length) {
  process.stdout.write(`FAIL ${failed.length} of ${cases + failed.length} R2 download cases\n`);
  process.exit(1);
}
process.stdout.write(`PASS ${cases} R2 download cases\n`);
