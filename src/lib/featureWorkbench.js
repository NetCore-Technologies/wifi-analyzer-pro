const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);

export function filterFeatureCatalog(features, { categoryTerms = [], query = "" } = {}) {
  if (!Array.isArray(features)) return [];
  const categories = new Set(Array.isArray(categoryTerms) ? categoryTerms : []);
  const needle = String(query ?? "").trim().toLocaleLowerCase();

  return features.filter(feature => {
    if (!isRecord(feature)) return false;
    if (categories.size && !categories.has(feature.category)) return false;
    if (!needle) return true;
    const searchable = [feature.id, feature.slug, feature.name, feature.category, feature.description]
      .filter(value => typeof value === "string")
      .join(" ")
      .toLocaleLowerCase();
    return searchable.includes(needle);
  });
}

export function buildFeaturePayloadTemplate(parameters) {
  if (!isRecord(parameters)) return {};

  return Object.fromEntries(Object.entries(parameters).map(([name, descriptor]) => {
    const type = String(descriptor ?? "").trim();
    const normalised = type.toLocaleLowerCase();

    if (/\[\]|array/.test(normalised)) return [name, []];
    if (/\bboolean\b|\bbool\b/.test(normalised)) return [name, false];
    if (/\bobject\b|\brecord\b|\bdict\b|\bjson\b/.test(normalised)) return [name, {}];

    if (type.includes("|")) {
      const firstChoice = type.split("|").map(choice => choice.trim()).find(Boolean);
      return [name, firstChoice ?? ""];
    }

    if (/\binteger\b|\bnumber\b|\bfloat\b|\bdouble\b/.test(normalised)) return [name, 0];
    return [name, ""];
  }));
}
