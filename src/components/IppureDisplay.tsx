import { useI18n, type MessageKey } from "../i18n";
import type { IppureResult } from "../types";

const IPPURE_ERROR_KIND_KEYS: Record<string, MessageKey> = {
  abandoned: "nodes.ippureErrorAbandoned",
  refused: "nodes.ippureErrorRefused",
  reset: "nodes.ippureErrorReset",
  timeout: "nodes.ippureErrorTimeout",
  dns: "nodes.ippureErrorDns",
  tls: "nodes.ippureErrorTls",
  auth: "nodes.ippureErrorAuth",
  blocked: "nodes.ippureErrorBlocked",
  limited: "nodes.ippureErrorLimited",
  endpoint: "nodes.ippureErrorEndpoint",
  response: "nodes.ippureErrorResponse",
  tunnel: "nodes.ippureErrorTunnel",
  core: "nodes.ippureErrorCore",
  status: "nodes.ippureErrorStatus",
};

function ippureErrorShort(
  error: string,
  kind: string | null | undefined,
  t: ReturnType<typeof useI18n>["t"],
) {
  if (kind) {
    const key = IPPURE_ERROR_KIND_KEYS[kind];
    if (key) return t(key);
  }
  // Cached results from before error_kind existed fall back to the same labels.
  const raw = error.toLowerCase();
  if (
    raw.includes("clash_api select status 400") ||
    raw.includes("clash_api select status 404") ||
    raw.includes("clash_api select status 405") ||
    raw.includes("clash_api select status 409") ||
    raw.includes("clash_api select status 422")
  ) {
    return t("nodes.ippureErrorAbandoned");
  }
  if (raw.includes("clash_api")) {
    return t("nodes.ippureErrorCore");
  }
  if (raw.includes("407") || raw.includes("proxy authentication")) {
    return t("nodes.ippureErrorAuth");
  }
  if (raw.includes("status 403")) {
    return t("nodes.ippureErrorBlocked");
  }
  if (raw.includes("status 429")) {
    return t("nodes.ippureErrorLimited");
  }
  if (raw.includes("ippure json:") || raw.includes("unexpected end of json")) {
    return t("nodes.ippureErrorResponse");
  }
  if (
    raw.includes("reset") ||
    raw.includes("rst") ||
    raw.includes("closed before")
  ) {
    return t("nodes.ippureErrorReset");
  }
  if (raw.includes("timed out") || raw.includes("timeout") || raw.includes("超时")) {
    return t("nodes.ippureErrorTimeout");
  }
  if (raw.includes("refused")) {
    return t("nodes.ippureErrorRefused");
  }
  if (raw.includes("dns") || raw.includes("resolve")) {
    return t("nodes.ippureErrorDns");
  }
  if (
    raw.includes("ssl") ||
    raw.includes("tls") ||
    raw.includes("certificate") ||
    raw.includes("handshake")
  ) {
    return t("nodes.ippureErrorTls");
  }
  if (/status (5\d\d|404)/.test(raw)) {
    return t("nodes.ippureErrorEndpoint");
  }
  return t("nodes.ippureFailed");
}

/** IPPure result nature: home broadband, datacenter-ish, or broadcast. */
export function ippureNatureKey(
  result?: IppureResult | null,
): "residential" | "datacenter" | "broadcast" | null {
  if (!result || result.error) return null;
  if (result.is_residential === true) return "residential";
  if (result.is_broadcast === true) return "broadcast";
  if (result.as_organization) return "datacenter";
  return null;
}

/** IPPure exit-IP / fraud score badge for node lists and cards. */
export function IppureDisplay({
  result,
  testing,
  compact = false,
  showNature = false,
}: {
  result?: IppureResult;
  testing: boolean;
  compact?: boolean;
  /** Render the IP nature badge inline (residential / datacenter / broadcast). */
  showNature?: boolean;
}) {
  const { t } = useI18n();
  if (testing) {
    return (
      <span className="lat-spinner" aria-label={t("nodes.ippureTesting")} />
    );
  }
  if (!result) {
    return <span className="ippure ippure-none">{t("nodes.ippureUntested")}</span>;
  }
  if (result.error) {
    return (
      <span className="ippure ippure-error" title={result.error}>
        {ippureErrorShort(result.error, result.error_kind, t)}
      </span>
    );
  }
  const risk = result.risk ?? "unknown";
  const riskLabels: Record<string, string> = {
    white: t("nodes.ippureRiskWhite"),
    green: t("nodes.ippureRiskGreen"),
    yellow: t("nodes.ippureRiskYellow"),
    orange: t("nodes.ippureRiskOrange"),
    red: t("nodes.ippureRiskRed"),
    black: t("nodes.ippureRiskBlack"),
  };
  const riskLabel = riskLabels[risk] ?? t("nodes.ippureRiskUnknown");
  const score = result.fraud_score;
  const geo = result.country_code ?? result.country ?? "";
  const scoreLabel = score != null ? String(score) : "?";
  const label = compact
    ? `${scoreLabel} ${riskLabel}`
    : [result.ip ?? (geo || "IP"), scoreLabel, riskLabel]
        .filter(Boolean)
        .join(" · ");
  const nature = ippureNatureKey(result);
  const natureLabel =
    nature === "residential"
      ? t("nodes.ippureResidential")
      : nature === "datacenter"
        ? t("nodes.ippureDatacenter")
        : nature === "broadcast"
          ? t("nodes.ippureBroadcast")
          : "";
  const detail = [
    result.ip,
    result.country,
    result.region,
    result.city,
    result.as_organization,
    natureLabel,
    riskLabel,
    score != null ? `score ${score}/100` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <span className={`ippure ippure-${risk}`} title={detail || undefined}>
      {showNature && natureLabel ? (
        <span
          className={`ippure-nature ippure-nature-${nature}`}
          title={natureLabel}
        >
          {natureLabel}
        </span>
      ) : null}
      {label}
    </span>
  );
}
