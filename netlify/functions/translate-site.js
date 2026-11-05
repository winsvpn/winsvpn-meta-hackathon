const GOOGLE_TRANSLATE_URL = "https://translation.googleapis.com/language/translate/v2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json"
};

function json(statusCode, body) {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify(body)
  };
}

function normalizeLocale(locale) {
  const value = String(locale || "en").trim();
  if (!/^[a-zA-Z-]{2,12}$/.test(value)) return "en";
  return value === "iw" ? "he" : value;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return json(405, { error: "method_not_allowed" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (_) {
    return json(400, { error: "invalid_json" });
  }

  const locale = normalizeLocale(payload.locale);
  const strings = Array.isArray(payload.strings)
    ? [...new Set(payload.strings.map((item) => String(item || "").trim()).filter(Boolean))]
    : [];

  if (locale === "en") return json(200, { translations: {} });
  if (strings.length === 0) return json(400, { error: "empty_strings" });
  if (strings.length > 140) return json(413, { error: "too_many_strings" });
  if (strings.some((item) => item.length > 1200)) {
    return json(413, { error: "string_too_long" });
  }

  const apiKey = process.env.GOOGLE_TRANSLATE_API_KEY;
  if (!apiKey) {
    return json(503, { error: "translation_api_not_configured" });
  }

  try {
    const response = await fetch(`${GOOGLE_TRANSLATE_URL}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        q: strings,
        source: "en",
        target: locale,
        format: "text"
      })
    });
    if (!response.ok) {
      return json(502, { error: "translation_failed" });
    }
    const data = await response.json();
    const translated = data?.data?.translations || [];
    const translations = {};
    strings.forEach((source, index) => {
      const translatedText = translated[index]?.translatedText;
      if (translatedText && translatedText !== source) translations[source] = translatedText;
    });
    return json(200, { translations });
  } catch (_) {
    return json(502, { error: "translation_unavailable" });
  }
};
