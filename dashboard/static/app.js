const scoredTargets = [
  ["windows-x86","Windows x64","Desktop applications",["windows-x64-installer","windows-x64-partner-center"],[]],
  ["windows-arm64","Windows arm64","Desktop applications",["windows-arm64-installer","windows-arm64-partner-center"],[]],
  ["macos-x86","macOS x86","Desktop applications",["macos-app-store-pkg"],["macos-developer-id-app"]],
  ["macos-arm64","macOS arm64","Desktop applications",["macos-app-store-pkg"],["macos-developer-id-app"]],
  ["linux-x86","Linux x64","Desktop applications",["linux-x64-package","linux-flathub-manifest","linux-snap-manifest"],[]],
  ["linux-arm64","Linux arm64","Desktop applications",["linux-arm64-package","linux-flathub-manifest","linux-snap-manifest"],[]],
  ["ios","iOS","Mobile applications",["ios-app-store-ipa"],[]],
  ["android","Android","Mobile applications",["android-phone-tablet-aab","android-tv-aab"],[]],
  ["chrome-extension","Chrome extension","Browser extensions",["chrome-extension-package","edge-extension-package"],[]],
  ["firefox-extension","Firefox extension","Browser extensions",["firefox-extension-package"],[]],
  ["watch-wear-os","Wear OS","Wearables",["wear-os-aab"],[]],
  ["apple-watch-watchos","Apple Watch/watchOS","Wearables",["ios-app-store-ipa"],[]],
  ["control-hub","control hub","Server deployment",[],[]],
  ["data-plane","data plane","Server deployment",[],[]],
  ["core-double-vpn","core/double-VPN","Server deployment",[],[]],
  ["smart-router","Smart Router","Server deployment",[],[]],
  ["gcp-three-server-proof","Three-server GCP proof","Server deployment",[],[]],
  ["signing-store-metadata","Signing and store metadata","Release governance",[],[]],
  ["winn-v3","Winn v3","Protocols",[],[]],
  ["winn-v1-awg-xray","Winn v1 AWG/Xray","Protocols",[],[]]
];
const operatorTargets = scoredTargets.flatMap((target) => {
  if (target[0] !== "chrome-extension") return [target];
  return [
    ["chrome-extension","Chrome extension","Browser extensions",["chrome-extension-package"],[]],
    ["edge-extension","Edge extension","Browser extensions",["edge-extension-package"],[]]
  ];
});
const requiredUploadTargets = [
  "android-phone-tablet-aab",
  "android-tv-aab",
  "wear-os-aab",
  "ios-app-store-ipa",
  "macos-app-store-pkg",
  "windows-x64-installer",
  "windows-x64-partner-center",
  "windows-arm64-installer",
  "windows-arm64-partner-center",
  "linux-x64-package",
  "linux-arm64-package",
  "linux-flathub-manifest",
  "linux-snap-manifest",
  "chrome-extension-package",
  "edge-extension-package",
  "firefox-extension-package"
];
const optionalUploadTargets = ["macos-developer-id-app"];
const engineeringIds = ["engineering", "runtime_proof"];
const storeIds = ["artifact", "signing", "store_metadata"];
const text = (value) => document.createTextNode(String(value ?? ""));
const el = (name, className, value) => {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (value !== undefined) node.append(text(value));
  return node;
};
const time = (value) => {
  const date = new Date(value);
  return value && !Number.isNaN(date.getTime()) ? date.toLocaleString() : "no current timestamp";
};
function detailRows(parent, item) {
  [
    item.reason,
    item.evidence_type ? "type: " + item.evidence_type : null,
    item.summary_code ? "evidence: " + item.summary_code : null,
    item.producer ? "producer: " + item.producer : null,
    item.observed_at ? "observed: " + time(item.observed_at) : null
  ].filter(Boolean).forEach((value) => parent.append(el("div", "detail", value)));
  (Array.isArray(item.artifacts) ? item.artifacts : []).forEach((artifact) => {
    parent.append(el(
      "div",
      "artifact",
      artifact.root + ":" + artifact.path + "\nsha256 " + artifact.sha256 + "\n" + artifact.bytes + " bytes, modified " + time(artifact.modified_at)
    ));
  });
}
function itemRow(item, blocker) {
  const details = el("details", blocker ? "blocker" : "");
  const summary = el("summary");
  const state = el(
    "span",
    blocker ? "blocker-kind" : "dimension-status " + item.status,
    blocker ? item.kind : item.status
  );
  summary.append(
    state,
    el("span", "", blocker ? item.id : item.label),
    el("span", "detail", blocker ? item.status : item.weight + "%")
  );
  details.append(summary);
  detailRows(details, item);
  return details;
}
function crossStoreRow(item) {
  const details = el("details", "");
  const summary = el("summary");
  const status = String(item.status || "unavailable");
  summary.append(
    el("span", "dimension-status " + status, status),
    el("span", "", item.target_id),
    el("span", "detail", "schema v" + item.receipt_schema_version)
  );
  details.append(summary);
  [
    item.reason,
    "release: " + item.release,
    "receipt: " + item.receipt,
    item.verified_at ? "verified: " + time(item.verified_at) : null,
    item.receipt_sha256 ? "receipt sha256: " + item.receipt_sha256 : null,
    item.artifact_sha256 ? "artifact sha256: " + item.artifact_sha256 : null
  ].filter(Boolean).forEach((value) => details.append(el("div", "detail", value)));
  return details;
}
function card(target) {
  const readiness = Math.max(0, Math.min(100, Number(target.readiness) || 0));
  const technical = Math.max(0, Math.min(100, Number(target.technical_readiness) || 0));
  const engineering = Math.max(0, Math.min(40, Number(target.engineering_readiness) || 0));
  const storeEvidence = Math.max(0, Math.min(60, Number(target.store_evidence_readiness) || 0));
  const status = String(target.status || "unavailable").toLowerCase();
  const node = el("article", "card");
  node.dataset.status = status;
  const top = el("div", "card-top");
  const title = el("div");
  title.append(el("h3", "", target.label), el("div", "target-id", target.id));
  top.append(title, el("span", "status " + status, status));
  node.append(top);
  const score = el("div", "score");
  score.append(
    el("strong", "", readiness + "% store-ready"),
    el("span", "", engineering + "% engineering/test"),
    el("span", "", storeEvidence + "% signed-artifact/store-upload"),
    el("span", "", technical + "% technical evidence")
  );
  node.append(score);
  const bar = el("div", "bar");
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-label", target.label + " store readiness");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  bar.setAttribute("aria-valuenow", String(readiness));
  const fill = el("i", "");
  fill.style.setProperty("--pct", readiness + "%");
  bar.append(fill);
  node.append(bar);
  node.append(el(
    "div",
    "timestamp",
    "last evidence: " + time(target.last_evidence_at) + "\nreceipt: " + (target.receipt || target.id + ".json")
  ));
  const uploadReceipts = el("div", "dimensions");
  uploadReceipts.append(el(
    "div",
    "section-label",
    "Mapped cross-store upload receipts: " + String(target.cross_store_status || "unavailable")
  ));
  const mappedReceipts = Array.isArray(target.cross_store_receipts) ? target.cross_store_receipts : [];
  if (mappedReceipts.length) mappedReceipts.forEach((item) => uploadReceipts.append(crossStoreRow(item)));
  else uploadReceipts.append(el("div", "detail", "No cross-store upload receipt applies to this target."));
  node.append(uploadReceipts);
  const optionalReceipts = Array.isArray(target.optional_cross_store_receipts) ? target.optional_cross_store_receipts : [];
  if ((target.optional_upload_targets || []).length) {
    const optional = el("div", "dimensions");
    optional.append(el(
      "div",
      "section-label",
      "Optional distribution receipts, not scored: " + String(target.optional_cross_store_status || "unavailable")
    ));
    optionalReceipts.forEach((item) => optional.append(crossStoreRow(item)));
    node.append(optional);
  }
  const dimensions = el("div", "dimensions");
  dimensions.append(el("div", "section-label", "Evidence dimensions"));
  (Array.isArray(target.dimensions) ? target.dimensions : []).forEach((item) => dimensions.append(itemRow(item, false)));
  node.append(dimensions);
  const blockers = el("div", "blockers");
  blockers.append(el("div", "section-label", "Owner and external blockers"));
  if (target.blocker_audit) blockers.append(itemRow(target.blocker_audit, false));
  const list = Array.isArray(target.blockers) ? target.blockers : [];
  if (list.length) list.forEach((item) => blockers.append(itemRow(item, true)));
  else blockers.append(el(
    "div",
    "detail",
    target.blocker_audit && target.blocker_audit.status === "verified"
      ? "Fresh blocker audit declares no owner or external blocker."
      : "Owner and external blocker disclosure is unverified until a fresh blocker audit is present."
  ));
  node.append(blockers);
  return node;
}
function renderTargets(targets) {
  const root = document.getElementById("target-groups");
  root.replaceChildren();
  const groups = new Map();
  targets.forEach((target) => {
    if (!groups.has(target.group)) groups.set(target.group, []);
    groups.get(target.group).push(target);
  });
  groups.forEach((groupTargets, group) => {
    const section = el("section", "");
    const heading = el("h2", "", group);
    const grid = el("div", "grid");
    groupTargets.forEach((target) => grid.append(card(target)));
    section.append(heading, grid);
    root.append(section);
  });
}
function renderUploadTargets(receipts) {
  const root = document.getElementById("upload-target-list");
  root.replaceChildren();
  receipts.forEach((receipt) => root.append(crossStoreRow(receipt)));
}
function renderBlockerCategories(categories) {
  const root = document.getElementById("blocker-category-list");
  root.replaceChildren();
  (Array.isArray(categories) ? categories : []).forEach((item) => {
    const node = el("article", "card");
    node.dataset.status = "blocked";
    const top = el("div", "card-top");
    top.append(
      el("h3", "", item.id),
      el("span", "status blocked", item.status || "open")
    );
    node.append(top);
    node.append(el("div", "detail", item.detail || ""));
    root.append(node);
  });
}
const failClosedCategories = [
  {id: "publication_hold", status: "open", detail: "DO-NOT-UPLOAD"},
  {id: "missing_upload_receipts", status: "open", detail: "0/16"},
  {id: "gcp_proof", status: "open", detail: "no valid fresh GCP proof"},
  {id: "agp_migration", status: "open", detail: "in progress"},
  {id: "macos_release_python", status: "open", detail: "owner prompt pending"},
  {id: "undisclosed_blocker_audits", status: "open", detail: String(operatorTargets.length)}
];
function emptyTarget(target) {
  return {
    id: target[0],
    label: target[1],
    group: target[2],
    upload_targets: target[3],
    optional_upload_targets: target[4],
    cross_store_status: target[3].length ? "unavailable" : "not_applicable",
    cross_store_receipts: [],
    optional_cross_store_status: target[4].length ? "unavailable" : "not_applicable",
    optional_cross_store_receipts: [],
    status: "unavailable",
    readiness: 0,
    technical_readiness: 0,
    engineering_readiness: 0,
    store_evidence_readiness: 0,
    dimensions: [],
    blockers: []
  };
}
function fallback(message) {
  window.clearTimeout(snapshotExpiryTimer);
  snapshotExpiryTimer = null;
  document.getElementById("connection").className = "connection error";
  document.getElementById("connection").textContent = "EVIDENCE UNAVAILABLE";
  const notice = document.getElementById("notice");
  notice.className = "notice error";
  notice.textContent = "Readiness withheld: " + message + " DO-NOT-UPLOAD. 0/16 required upload receipts (strict store denominator). 0/20 engineering/operator targets. 21 blocker-audit entries are not a store denominator. No valid fresh GCP proof. AGP migration in progress. macOS release Python owner prompt pending. Workers and source presence are not PASS.";
  document.getElementById("publication-hold").className = "notice error";
  document.getElementById("publication-hold").textContent = "DO-NOT-UPLOAD";
  document.getElementById("publication").textContent = "DO-NOT-UPLOAD";
  document.getElementById("overall").textContent = "0%";
  document.getElementById("engineering").textContent = "0%";
  document.getElementById("store-evidence").textContent = "0%";
  document.getElementById("technical").textContent = "0%";
  document.getElementById("upload-coverage").textContent = "0 / " + requiredUploadTargets.length;
  document.getElementById("ready-count").textContent = "0 / " + scoredTargets.length;
  document.getElementById("pending-count").textContent = scoredTargets.length + " targets, " + requiredUploadTargets.length + " uploads";
  document.getElementById("failed-count").textContent = "0 targets, 0 uploads";
  document.getElementById("gcp-proof").textContent = "no valid fresh proof";
  document.getElementById("agp-migration").textContent = "in progress";
  document.getElementById("macos-python").textContent = "owner prompt pending";
  document.getElementById("freshness").textContent = "unavailable";
  document.getElementById("owner-blockers").textContent = "0";
  document.getElementById("external-blockers").textContent = "0";
  document.getElementById("undisclosed-audits").textContent = String(operatorTargets.length);
  document.getElementById("blocker-category-count").textContent = String(failClosedCategories.length);
  document.getElementById("generated-at").textContent = "unavailable";
  document.getElementById("evidence-root").textContent = "local only";
  renderBlockerCategories(failClosedCategories);
  renderUploadTargets(requiredUploadTargets.map((targetId) => ({
    target_id: targetId,
    receipt: ".artifacts/upload-receipts/" + targetId + ".json",
    receipt_schema_version: 2,
    release: "1.0.17+34",
    status: "unavailable",
    reason: "local evidence validation failed"
  })));
  renderTargets(operatorTargets.map(emptyTarget));
}
const sameArray = (left, right) => Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]);
function validCrossStoreReceipt(receipt, targetId) {
  if (
    !receipt ||
    receipt.target_id !== targetId ||
    receipt.receipt_schema_version !== 2 ||
    receipt.release !== "1.0.17+34" ||
    receipt.receipt !== ".artifacts/upload-receipts/" + targetId + ".json" ||
    !["verified", "missing", "invalid", "stale", "unavailable"].includes(receipt.status)
  ) return false;
  if (["verified", "stale"].includes(receipt.status)) {
    return /^[0-9a-f]{64}$/.test(String(receipt.receipt_sha256 || "")) &&
      /^[0-9a-f]{64}$/.test(String(receipt.artifact_sha256 || "")) &&
      !Number.isNaN(new Date(receipt.verified_at).getTime());
  }
  return receipt.verified_at === null && receipt.receipt_sha256 === null && receipt.artifact_sha256 === null;
}
function validStatusCounts(receipts, counts) {
  if (!counts) return false;
  const expected = {verified: 0, missing: 0, invalid: 0, stale: 0, unavailable: 0};
  for (const receipt of receipts) {
    if (!Object.prototype.hasOwnProperty.call(expected, receipt.status)) return false;
    expected[receipt.status] += 1;
  }
  return Object.keys(expected).every((status) => expected[status] === Number(counts[status]));
}
function aggregateCrossStoreStatus(receipts, applies) {
  if (!applies) return "not_applicable";
  const statuses = receipts.map((receipt) => receipt.status);
  if (statuses.length && statuses.every((status) => status === "unavailable")) return "unavailable";
  if (statuses.every((status) => status === "verified")) return "verified";
  if (statuses.includes("invalid")) return "invalid";
  if (statuses.includes("stale")) return "stale";
  if (statuses.includes("verified")) return "partial";
  if (statuses.includes("unavailable")) return "unavailable";
  return "missing";
}
function validCrossStoreState(state) {
  const crossStore = state.cross_store;
  if (
    !crossStore ||
    crossStore.release !== "1.0.17+34" ||
    crossStore.receipt_schema_version !== 2 ||
    crossStore.release_input_index !== ".artifacts/release-inputs/RELEASE_INPUT_INDEX.json" ||
    crossStore.receipt_directory !== ".artifacts/upload-receipts" ||
    crossStore.required_upload_target_count !== 16 ||
    !sameArray(crossStore.required_upload_targets, requiredUploadTargets) ||
    !Array.isArray(crossStore.receipts) ||
    crossStore.receipts.length !== 16 ||
    crossStore.optional_upload_target_count !== 1 ||
    !sameArray(crossStore.optional_upload_targets, optionalUploadTargets) ||
    !Array.isArray(crossStore.optional_receipts) ||
    crossStore.optional_receipts.length !== 1
  ) return false;
  const byId = new Map();
  const allReceipts = [...crossStore.receipts, ...crossStore.optional_receipts];
  const knownTargets = [...requiredUploadTargets, ...optionalUploadTargets];
  for (const receipt of allReceipts) {
    if (!validCrossStoreReceipt(receipt, receipt && receipt.target_id) || byId.has(receipt.target_id) || !knownTargets.includes(receipt.target_id)) return false;
    byId.set(receipt.target_id, receipt);
  }
  return byId.size === 17 &&
    validStatusCounts(crossStore.receipts, crossStore.status_counts) &&
    validStatusCounts(crossStore.optional_receipts, crossStore.optional_status_counts) &&
    requiredUploadTargets.includes("android-tv-aab") &&
    requiredUploadTargets.includes("edge-extension-package") &&
    requiredUploadTargets.includes("chrome-extension-package");
}
function validTargets(targets, contractList) {
  const expected = new Map(contractList.map((target) => [target[0], target]));
  return Array.isArray(targets) &&
    targets.length === expected.size &&
    targets.every((target) => {
      const contract = expected.get(target.id);
      return contract &&
        target.label === contract[1] &&
        target.group === contract[2] &&
        sameArray(target.upload_targets, contract[3]) &&
        sameArray(target.optional_upload_targets, contract[4]);
    }) &&
    new Set(targets.map((target) => target.id)).size === expected.size;
}
function validDerivedScores(state) {
  if (!validTargets(state.targets, scoredTargets) || !validCrossStoreState(state)) return false;
  const allReceipts = [...state.cross_store.receipts, ...state.cross_store.optional_receipts];
  const topReceipts = new Map(allReceipts.map((receipt) => [receipt.target_id, receipt]));
  let overall = 0;
  let technicalOverall = 0;
  let engineeringOverall = 0;
  let storeOverall = 0;
  let ready = 0;
  for (const target of state.targets) {
    if (
      !Array.isArray(target.dimensions) ||
      target.dimensions.length !== 5 ||
      !target.blocker_audit ||
      !Array.isArray(target.blockers) ||
      !Array.isArray(target.cross_store_receipts) ||
      target.cross_store_receipts.length !== target.upload_targets.length ||
      !Array.isArray(target.optional_cross_store_receipts) ||
      target.optional_cross_store_receipts.length !== target.optional_upload_targets.length
    ) return false;
    const mapped = target.cross_store_receipts.every((receipt, index) =>
      receipt.target_id === target.upload_targets[index] &&
      validCrossStoreReceipt(receipt, target.upload_targets[index]) &&
      JSON.stringify(receipt) === JSON.stringify(topReceipts.get(receipt.target_id))
    );
    const optionalMapped = target.optional_cross_store_receipts.every((receipt, index) =>
      receipt.target_id === target.optional_upload_targets[index] &&
      validCrossStoreReceipt(receipt, target.optional_upload_targets[index]) &&
      JSON.stringify(receipt) === JSON.stringify(topReceipts.get(receipt.target_id))
    );
    if (!mapped || !optionalMapped) return false;
    const expectedCrossStoreStatus = aggregateCrossStoreStatus(
      target.cross_store_receipts,
      target.upload_targets.length > 0
    );
    const expectedOptionalStatus = aggregateCrossStoreStatus(
      target.optional_cross_store_receipts,
      target.optional_upload_targets.length > 0
    );
    if (
      target.cross_store_status !== expectedCrossStoreStatus ||
      target.optional_cross_store_status !== expectedOptionalStatus
    ) return false;
    const crossStoreVerified = expectedCrossStoreStatus === "verified" || expectedCrossStoreStatus === "not_applicable";
    const technical = target.dimensions.reduce(
      (sum, item) => sum + (item.status === "verified" ? Number(item.weight) : 0),
      0
    );
    const engineering = target.dimensions.reduce(
      (sum, item) => sum + (engineeringIds.includes(item.id) && item.status === "verified" ? Number(item.weight) : 0),
      0
    );
    const storeEvidence = target.dimensions.reduce(
      (sum, item) => sum + (storeIds.includes(item.id) && item.status === "verified" ? Number(item.weight) : 0),
      0
    );
    const storeVerified = storeIds.every((id) =>
      target.dimensions.some((item) => item.id === id && item.status === "verified")
    );
    if (engineering > 40 || storeEvidence > 60 || engineering + storeEvidence !== technical) return false;
    const readiness = target.blocker_audit.status === "verified" && target.blockers.length === 0 && crossStoreVerified && storeVerified ? technical : 0;
    const shouldBeReady = readiness === 100 && technical === 100 && engineering === 40 && storeEvidence === 60;
    if (
      technical !== Number(target.technical_readiness) ||
      engineering !== Number(target.engineering_readiness) ||
      storeEvidence !== Number(target.store_evidence_readiness) ||
      readiness !== Number(target.readiness) ||
      (target.status === "ready") !== shouldBeReady
    ) return false;
    if (target.status === "ready" && (engineering !== 40 || !storeVerified || Number(target.store_evidence_readiness) !== 60)) return false;
    overall += readiness;
    technicalOverall += technical;
    engineeringOverall += engineering;
    storeOverall += storeEvidence;
    if (target.status === "ready") ready += 1;
  }
  return Math.floor(overall / state.targets.length + .5) === Number(state.overall_readiness) &&
    Math.floor(technicalOverall / state.targets.length + .5) === Number(state.overall_technical_readiness) &&
    Math.floor(engineeringOverall / state.targets.length + .5) === Number(state.overall_engineering_readiness) &&
    Math.floor(storeOverall / state.targets.length + .5) === Number(state.overall_store_evidence_readiness) &&
    ready === Number(state.ready_targets) &&
    state.targets.length === Number(state.target_count);
}
function validOperatorTargets(state) {
  if (!validTargets(state.operator_targets, operatorTargets)) return false;
  const chrome = state.operator_targets.find((target) => target.id === "chrome-extension");
  const edge = state.operator_targets.find((target) => target.id === "edge-extension");
  if (!chrome || !edge) return false;
  if (!sameArray(chrome.upload_targets, ["chrome-extension-package"])) return false;
  if (!sameArray(edge.upload_targets, ["edge-extension-package"])) return false;
  if (chrome.upload_targets.includes("edge-extension-package")) return false;
  if (Number(edge.engineering_readiness) !== Number(chrome.engineering_readiness)) return false;
  if (Number(edge.technical_readiness) !== Number(chrome.technical_readiness)) return false;
  if (Number(edge.store_evidence_readiness) !== Number(chrome.store_evidence_readiness)) return false;
  if (JSON.stringify(edge.dimensions || []) !== JSON.stringify(chrome.dimensions || [])) return false;
  if (JSON.stringify(edge.blockers || []) !== JSON.stringify(chrome.blockers || [])) return false;
  if (JSON.stringify(edge.blocker_audit || null) !== JSON.stringify(chrome.blocker_audit || null)) return false;
  if (Number(chrome.engineering_readiness) > 40 || Number(edge.engineering_readiness) > 40) return false;
  if (Number(chrome.store_evidence_readiness) > 60 || Number(edge.store_evidence_readiness) > 60) return false;
  const represented = new Set();
  for (const target of state.operator_targets) {
    if (
      !Array.isArray(target.cross_store_receipts) ||
      target.cross_store_receipts.length !== target.upload_targets.length
    ) return false;
    const expectedStatus = aggregateCrossStoreStatus(
      target.cross_store_receipts,
      target.upload_targets.length > 0
    );
    if (target.cross_store_status !== expectedStatus) return false;
    const mappedMissing = target.cross_store_receipts.some((receipt) => receipt.status !== "verified");
    if (mappedMissing && (target.status === "ready" || Number(target.readiness) > 0)) return false;
    if (target.status === "ready" && (Number(target.engineering_readiness) !== 40 || Number(target.store_evidence_readiness) !== 60 || !storeIds.every((id) => (target.dimensions || []).some((item) => item.id === id && item.status === "verified")))) return false;
    if (!Number.isFinite(Number(target.engineering_readiness)) || !Number.isFinite(Number(target.store_evidence_readiness))) return false;
    target.upload_targets.forEach((item) => represented.add(item));
  }
  return represented.size === 16 &&
    requiredUploadTargets.every((item) => represented.has(item));
}
function validBlockerSummary(state) {
  const summary = state.blocker_summary;
  if (!summary || !Array.isArray(summary.items)) return false;
  const owner = summary.items.filter((item) => item.kind === "owner").length;
  const external = summary.items.filter((item) => item.kind === "external").length;
  const undisclosed = summary.items.filter((item) => item.kind === "undisclosed").length;
  if (
    owner !== Number(summary.owner) ||
    external !== Number(summary.external) ||
    undisclosed !== Number(summary.undisclosed_audits) ||
    owner + external + undisclosed !== Number(summary.count)
  ) return false;
  const chrome = state.operator_targets.find((target) => target.id === "chrome-extension");
  const chromeBlockers = Array.isArray(chrome && chrome.blockers) ? chrome.blockers : [];
  for (const blocker of chromeBlockers) {
    if (!summary.items.some((item) =>
      item.target_id === "edge-extension" &&
      item.blocker_id === blocker.id &&
      item.kind === blocker.kind
    )) return false;
  }
  if (chrome && chrome.blocker_audit && chrome.blocker_audit.status !== "verified") {
    if (!summary.items.some((item) => item.target_id === "edge-extension" && item.kind === "undisclosed")) return false;
  }
  return true;
}
function scoredOutcome(status) {
  return status === "ready" ? "ready" : status === "partial" ? "partial" : status === "stale" ? "stale" : status === "unverified" ? "pending" : status === "unavailable" ? "unavailable" : "failed";
}
function receiptOutcome(status) {
  return status === "verified" ? "verified" : status === "missing" ? "pending" : status === "stale" ? "stale" : status === "unavailable" ? "unavailable" : "failed";
}
function roundedPercent(verified, required) {
  if (!(required > 0) || !(verified > 0)) return 0;
  return verified >= required ? 100 : Math.floor(verified * 100 / required + .5);
}
function engineeringOutcome(target) {
  const dims = (target.dimensions || []).filter((item) => engineeringIds.includes(item.id));
  if (dims.length !== engineeringIds.length) return "unavailable";
  const statuses = dims.map((item) => item.status);
  if (statuses.every((status) => status === "verified")) return "verified";
  if (statuses.some((status) => status === "failed" || status === "invalid")) return "failed";
  if (statuses.includes("stale")) return "stale";
  if (statuses.includes("missing")) return "pending";
  return "failed";
}
function countsMatch(expected, actual, keys) {
  return !!actual && keys.every((key) => Number(actual[key]) === expected[key]);
}
function validCoverage(state) {
  const coverage = state.coverage;
  const freshness = state.freshness;
  if (!coverage || !freshness || !coverage.scored_targets || !coverage.engineering || !coverage.store_upload) return false;
  const scored = {ready: 0, pending: 0, failed: 0, stale: 0, partial: 0, unavailable: 0};
  const engineering = {verified: 0, pending: 0, failed: 0, stale: 0, unavailable: 0};
  let verifiedDims = 0;
  let pendingDims = 0;
  let failedDims = 0;
  let staleDims = 0;
  let allStaleDims = 0;
  for (const target of state.targets || []) {
    scored[scoredOutcome(String(target.status || "unavailable"))] += 1;
    engineering[engineeringOutcome(target)] += 1;
    for (const item of target.dimensions || []) {
      if (item.status === "stale") allStaleDims += 1;
      if (!engineeringIds.includes(item.id)) continue;
      if (item.status === "verified") verifiedDims += 1;
      else if (item.status === "missing") pendingDims += 1;
      else if (item.status === "failed" || item.status === "invalid") failedDims += 1;
      else if (item.status === "stale") staleDims += 1;
    }
  }
  const store = {verified: 0, pending: 0, failed: 0, stale: 0, unavailable: 0};
  const optional = {verified: 0, pending: 0, failed: 0, stale: 0, unavailable: 0};
  for (const receipt of state.cross_store.receipts || []) store[receiptOutcome(String(receipt.status || "unavailable"))] += 1;
  for (const receipt of state.cross_store.optional_receipts || []) optional[receiptOutcome(String(receipt.status || "unavailable"))] += 1;
  const scoredReq = scoredTargets.length;
  const uploadReq = requiredUploadTargets.length;
  const operatorCardCount = operatorTargets.length;
  const engineeringReq = scoredReq * engineeringIds.length;
  const storePercent = roundedPercent(store.verified, uploadReq);
  const engineeringPercent = roundedPercent(verifiedDims, engineeringReq);
  if (scoredReq !== 20 || uploadReq !== 16 || operatorCardCount !== 21) return false;
  if (uploadReq === operatorCardCount || scoredReq === operatorCardCount) return false;
  if (coverage.store_upload.required_receipts === operatorCardCount) return false;
  if (coverage.scored_targets.required !== scoredReq || !countsMatch(scored, coverage.scored_targets, Object.keys(scored))) return false;
  if (
    coverage.engineering.required_targets !== scoredReq ||
    coverage.engineering.required_dimensions !== engineeringReq ||
    coverage.engineering.verified_targets !== engineering.verified ||
    coverage.engineering.pending_targets !== engineering.pending ||
    coverage.engineering.failed_targets !== engineering.failed ||
    coverage.engineering.stale_targets !== engineering.stale ||
    coverage.engineering.unavailable_targets !== engineering.unavailable ||
    coverage.engineering.verified_dimensions !== verifiedDims ||
    coverage.engineering.pending_dimensions !== pendingDims ||
    coverage.engineering.failed_dimensions !== failedDims ||
    coverage.engineering.stale_dimensions !== staleDims ||
    coverage.engineering.percent !== engineeringPercent
  ) return false;
  if (
    coverage.store_upload.required_receipts !== uploadReq ||
    !countsMatch(store, coverage.store_upload, Object.keys(store)) ||
    coverage.store_upload.percent !== storePercent ||
    coverage.store_upload.optional_receipts !== optionalUploadTargets.length ||
    coverage.store_upload.optional_verified !== optional.verified ||
    coverage.store_upload.optional_pending !== optional.pending ||
    coverage.store_upload.optional_failed !== optional.failed ||
    coverage.store_upload.optional_stale !== optional.stale ||
    coverage.store_upload.optional_unavailable !== optional.unavailable
  ) return false;
  if ((store.pending + store.failed + store.stale + store.unavailable) > 0 && (storePercent === 100 || Number(state.overall_readiness) === 100)) return false;
  if (verifiedDims === 0 && engineeringPercent !== 0) return false;
  if (
    Number(freshness.max_age_seconds) !== Number(state.max_evidence_age_seconds) ||
    Number(freshness.stale_targets) !== scored.stale ||
    Number(freshness.stale_upload_receipts) !== store.stale ||
    Number(freshness.stale_dimensions) !== allStaleDims
  ) return false;
  return true;
}
function claimsReadinessFromMissingReceipts(state) {
  const incomplete = (state.cross_store.receipts || []).some((receipt) => receipt.status !== "verified");
  return incomplete && (Number(state.overall_readiness) === 100 || Number((state.coverage && state.coverage.store_upload || {}).percent) === 100);
}
function verifiedSummary(target, dimensionId, summaryCode) {
  return !!target && (target.dimensions || []).some((item) =>
    item.id === dimensionId && item.status === "verified" && item.summary_code === summaryCode
  );
}
function validCurrentPosture(state) {
  const posture = state.current_posture;
  const coverage = state.coverage && state.coverage.store_upload;
  if (
    !posture ||
    !coverage ||
    posture.publication_hold !== "DO-NOT-UPLOAD" ||
    posture.store_upload_authorized !== false ||
    !posture.upload_receipts ||
    Number(posture.upload_receipts.verified) !== Number(coverage.verified) ||
    Number(posture.upload_receipts.required) !== 16 ||
    !["pending", "unavailable", "incomplete", "complete"].includes(String(posture.upload_receipts.status)) ||
    (Number(coverage.verified) !== 16 && posture.upload_receipts.status === "complete") ||
    (Number(coverage.verified) === 16 && posture.upload_receipts.status !== "complete") ||
    (Number(coverage.verified) === 0 && Number(coverage.unavailable) === 16 && posture.upload_receipts.status !== "unavailable") ||
    (Number(coverage.verified) === 0 && Number(coverage.unavailable) !== 16 && posture.upload_receipts.status !== "pending")
  ) return false;
  const gcpTarget = (state.targets || []).find((target) => target.id === "gcp-three-server-proof");
  const gcpVerified = verifiedSummary(gcpTarget, "runtime_proof", "gcp_proof_acceptance");
  if (
    !posture.gcp_proof ||
    posture.gcp_proof.fresh !== gcpVerified ||
    (gcpVerified && posture.gcp_proof.status !== "verified") ||
    (!gcpVerified && posture.gcp_proof.status === "verified") ||
    (!gcpVerified && String(posture.gcp_proof.reason || "").indexOf("no valid fresh GCP proof") < 0)
  ) return false;
  const android = (state.targets || []).find((target) => target.id === "android");
  const wear = (state.targets || []).find((target) => target.id === "watch-wear-os");
  const agpComplete = verifiedSummary(android, "artifact", "agp_migration_complete") &&
    verifiedSummary(wear, "artifact", "agp_migration_complete");
  if (
    !posture.agp_migration ||
    (agpComplete && posture.agp_migration.status !== "complete") ||
    (!agpComplete && posture.agp_migration.status !== "in_progress")
  ) return false;
  const pythonAuthenticated = ["macos-arm64", "macos-x86", "signing-store-metadata"].some((targetId) =>
    verifiedSummary((state.targets || []).find((target) => target.id === targetId), "engineering", "macos_release_python_runtime")
  );
  if (
    !posture.macos_release_python ||
    (pythonAuthenticated && posture.macos_release_python.status !== "authenticated") ||
    (!pythonAuthenticated && posture.macos_release_python.status !== "owner_prompt_pending")
  ) return false;
  const categories = posture.active_blocker_categories;
  if (!Array.isArray(categories) || !categories.length || categories[0].id !== "publication_hold" || categories[0].detail !== "DO-NOT-UPLOAD") return false;
  const ids = categories.map((item) => item.id);
  if (new Set(ids).size !== ids.length) return false;
  if (Number(posture.upload_receipts.verified) !== 16 && !ids.includes("missing_upload_receipts")) return false;
  if (!gcpVerified && !ids.includes("gcp_proof")) return false;
  if (!agpComplete && !ids.includes("agp_migration")) return false;
  if (!pythonAuthenticated && !ids.includes("macos_release_python")) return false;
  const summary = state.blocker_summary || {};
  if (Number(summary.undisclosed_audits) > 0 && !ids.includes("undisclosed_blocker_audits")) return false;
  if (Number(summary.owner) > 0 && !ids.includes("owner_blockers")) return false;
  if (Number(summary.external) > 0 && !ids.includes("external_blockers")) return false;
  return true;
}
function currentSnapshot(state) {
  const generated = new Date(state.generated_at);
  const expires = new Date(state.snapshot_expires_at);
  const now = Date.now();
  return !Number.isNaN(generated.getTime()) &&
    !Number.isNaN(expires.getTime()) &&
    generated.getTime() <= now + 300000 &&
    expires.getTime() > now &&
    expires.getTime() > generated.getTime();
}
let delay = 5000;
let snapshotExpiryTimer = null;
async function refresh() {
  const controller = new AbortController();
  const requestTimeout = window.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("/api/state", {
      cache: "no-store", headers: {"Accept": "application/json"}, signal: controller.signal
    });
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || "HTTP " + response.status);
    if (
      state.schema_version !== 8 ||
      state.receipt_schema_version !== 4 ||
      state.cross_store_receipt_schema_version !== 2 ||
      state.release !== "1.0.17+34" ||
      !state.local_only ||
      state.source !== "verified-local-evidence" ||
      !/^[0-9a-f]{64}$/.test(String(state.contract_sha256 || "")) ||
      !validDerivedScores(state) ||
      !validOperatorTargets(state) ||
      !validBlockerSummary(state) ||
      !validCoverage(state) ||
      !validCurrentPosture(state) ||
      claimsReadinessFromMissingReceipts(state) ||
      !currentSnapshot(state)
    ) throw new Error("local evidence state is incomplete, expired, or invalid");
    window.clearTimeout(snapshotExpiryTimer);
    snapshotExpiryTimer = window.setTimeout(
      () => fallback("local evidence snapshot expired"),
      Math.max(0, Date.parse(state.snapshot_expires_at) - Date.now())
    );
    delay = Math.max(2000, Math.min(60000, (Number(state.refresh_seconds) || 5) * 1000));
    document.getElementById("connection").className = "connection live";
    document.getElementById("connection").textContent = "LIVE, " + Math.round(delay / 1000) + "S";
    const evidenceWindow = state.max_evidence_age_seconds < 172800
      ? Math.round(state.max_evidence_age_seconds / 3600) + " hours"
      : Math.round(state.max_evidence_age_seconds / 86400) + " days";
    document.getElementById("notice").className = "notice";
    document.getElementById("notice").textContent =
      "Local only. DO-NOT-UPLOAD. Release " + state.release +
      " dashboard receipt schema 4 and all 16 required mapped cross-store schema-v2 receipts are required, including android-tv-aab. Store denominator is 16 upload targets, not 20 engineering/operator targets and not 21 Chrome/Edge blocker-audit entries. Engineering/test evidence cannot make a card store-ready. Plans, handoffs, unit tests, workers, and source presence are not receipts. Pending missing receipts are not PASS. Failed evidence is counted separately from pending work. Chrome and Edge are distinct operator cards; scored Chrome still requires both upload receipts. macOS Developer ID is optional, displayed separately, and never affects App Store readiness. Evidence and referenced artifacts expire after " +
      evidenceWindow +
      ". Any owner/external blocker or missing, stale, failed, invalid, substituted, or stale-release required evidence zeroes store-ready progress while preserving separate technical evidence.";
    const staleTotal = Number(state.freshness.stale_targets) + Number(state.freshness.stale_upload_receipts) + Number(state.freshness.stale_dimensions);
    const posture = state.current_posture;
    document.getElementById("publication-hold").className = "notice error";
    document.getElementById("publication-hold").textContent = posture.publication_hold;
    document.getElementById("publication").textContent = posture.publication_hold;
    document.getElementById("overall").textContent = state.overall_readiness + "%";
    document.getElementById("engineering").textContent = state.coverage.engineering.percent + "%";
    document.getElementById("store-evidence").textContent = state.coverage.store_upload.percent + "%";
    document.getElementById("technical").textContent = state.overall_technical_readiness + "%";
    document.getElementById("upload-coverage").textContent = state.coverage.store_upload.verified + " / " + state.coverage.store_upload.required_receipts;
    document.getElementById("ready-count").textContent = state.ready_targets + " / " + state.target_count;
    document.getElementById("pending-count").textContent = state.coverage.scored_targets.pending + " targets, " + state.coverage.store_upload.pending + " uploads";
    document.getElementById("failed-count").textContent = state.coverage.scored_targets.failed + " targets, " + state.coverage.store_upload.failed + " uploads";
    document.getElementById("gcp-proof").textContent = posture.gcp_proof.fresh ? "fresh proof verified" : "no valid fresh proof";
    document.getElementById("agp-migration").textContent = posture.agp_migration.status === "complete" ? "complete" : "in progress";
    document.getElementById("macos-python").textContent = posture.macos_release_python.status === "authenticated" ? "authenticated" : "owner prompt pending";
    document.getElementById("freshness").textContent = evidenceWindow + ", " + staleTotal + " stale";
    document.getElementById("owner-blockers").textContent = String(state.blocker_summary.owner);
    document.getElementById("external-blockers").textContent = String(state.blocker_summary.external);
    document.getElementById("undisclosed-audits").textContent = String(state.blocker_summary.undisclosed_audits);
    document.getElementById("blocker-category-count").textContent = String(posture.active_blocker_categories.length);
    document.getElementById("generated-at").textContent = time(state.generated_at);
    document.getElementById("evidence-root").textContent = state.evidence_directory;
    renderBlockerCategories(posture.active_blocker_categories);
    renderUploadTargets(state.cross_store.receipts);
    renderTargets(state.operator_targets);
  } catch (error) {
    fallback(error instanceof Error ? error.message : "unknown dashboard error");
  } finally {
    window.clearTimeout(requestTimeout);
    window.setTimeout(refresh, delay);
  }
}
fallback("waiting for the first local evidence snapshot");
refresh();
