const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);
const BOUNDED_COLLECTION_WORDS = /\b(?:records?|radios|entries|observations|samples|edges|profiles|assets|services|switches|firewalls|events|links|candidates|rules|deliveries|reports|networks|devices|interfaces|channels|clients|sites|options|measurements|metrics|snapshots|ports|vlans|routes|peers|policies|alerts|findings|dependencies|domains|certificates|subnets|leases|flows|packets|frames|results|objects|windows|segments|subscriptions|endpoints|applications|requirements|capabilities|transitions|counters|rollups|access points)\b/i;

export function filterFeatureCatalog(features, { categoryTerms = [], query = "" } = {}) {
  if (!Array.isArray(features)) return [];
  const categories = new Set(Array.isArray(categoryTerms) ? categoryTerms : []);
  const needle = String(query ?? "").trim().toLocaleLowerCase();
  return features.filter(feature => {
    if (!isRecord(feature)) return false;
    if (categories.size && !categories.has(feature.category)) return false;
    if (!needle) return true;
    const searchable = [feature.id, feature.slug, feature.name, feature.category, feature.description]
      .filter(value => typeof value === "string").join(" ").toLocaleLowerCase();
    return searchable.includes(needle);
  });
}

export function getFeatureParameterKind(descriptor, parameterName = "") {
  const description = String(descriptor ?? "").trim();
  const normalised = description.toLocaleLowerCase();
  const name = String(parameterName ?? "").trim().toLocaleLowerCase();
  if (description.includes("|")) return "enum";
  if (/\[\]|\barray\b|\blist\b|\bcollection\b/.test(normalised)) return "array";
  if (/\bboolean\b|\bbool\b|\btrue\/false\b/.test(normalised)) return "boolean";
  if (name === "text" || name.endsWith("_text") || name.endsWith("_query")) return "text";
  if (/\binteger\b/.test(normalised)) return "integer";
  if (/\bnumber\b|\bnumeric\b|\bfloat\b|\bdouble\b/.test(normalised)) return "number";
  if (/\bstring\b|\btext\b|\bidentifier\b|\burl\b|\buri\b/.test(normalised)) return "text";
  if (/\bobject\b|\bdict\b|\bdictionary\b|\bjson\b|\bmap\b|\bkey-value\b/.test(normalised)) return "object";
  const boundedCollection = /\b(?:up to|at most|no more than)\s+\d+|\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+to\s+(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)|\bbetween\s+(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+and\s+(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)|\b\d+\s*[-–]\s*\d+\b/i.test(description);
  if (boundedCollection && BOUNDED_COLLECTION_WORDS.test(normalised)) return "array";
  return "json";
}

export function getFeatureParameterChoices(descriptor) {
  if (typeof descriptor !== "string" || !descriptor.includes("|")) return [];
  return [...new Set(descriptor.split("|").map(choice => choice.trim()).filter(Boolean))];
}

export function parseFeatureParameterValue(text, kind) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error("Enter valid JSON: " + (error instanceof Error ? error.message : "invalid syntax"));
  }
  if (kind === "array" && !Array.isArray(value)) throw new Error("This parameter requires a JSON array.");
  if (kind === "object" && !isRecord(value)) throw new Error("This parameter requires a JSON object.");
  return value;
}

export function buildFeaturePayloadTemplate(parameters) {
  if (!isRecord(parameters)) return {};
  return Object.fromEntries(Object.entries(parameters).map(([name, descriptor]) => {
    const kind = getFeatureParameterKind(descriptor, name);
    if (kind === "array") return [name, []];
    if (kind === "boolean") return [name, false];
    if (kind === "object" || kind === "json") return [name, {}];
    if (kind === "enum") return [name, getFeatureParameterChoices(descriptor)[0] ?? ""];
    if (kind === "integer" || kind === "number") return [name, 0];
    return [name, ""];
  }));
}
