import type { BalanceItem, ProfileView, QuotaInfo } from "./api";

export interface Glm52PoolStats {
  totalAccounts: number;
  usedAccounts: number;
  remainingAccounts: number;
  usedUnits: number;
  totalUnits: number;
}

/**
 * 选出代表"主力模型剩余额度"的条目。
 * 当前套餐主力是 GLM-5.3（日额度 300 万），优先取不含 flash 的 GLM-5.3；
 * 找不到时依次回退：GLM-5.3-Flash → 任意含 glm 的条目（防套餐结构再变时统计全空）。
 */
export function findGlm52Balance(quota?: QuotaInfo): BalanceItem | undefined {
  const balances = quota?.balances ?? [];
  const name = (item: BalanceItem) => item.show_name.trim().toLowerCase();
  return (
    balances.find((b) => name(b).includes("glm-5.3") && !name(b).includes("flash")) ??
    balances.find((b) => name(b).includes("glm-5.3")) ??
    balances.find((b) => name(b).includes("glm"))
  );
}

/**
 * 该账号在服务端是否有生效套餐（已激活）。
 * `plan_status === "no_plan"` 或 balances 为空都算未激活（新号尚未在客户端发过首句话）。
 */
export function isPlanActive(quota?: QuotaInfo): boolean {
  if (!quota || quota.error) return false;
  if (quota.plan_status === "no_plan") return false;
  return (quota.balances?.length ?? 0) > 0;
}

export function glm52Remaining(quota?: QuotaInfo): number | null {
  const item = findGlm52Balance(quota);
  if (!item) return null;
  if (Number.isFinite(item.remaining_units)) return item.remaining_units;
  if (Number.isFinite(item.total_units) && Number.isFinite(item.used_units)) {
    return Math.max(0, item.total_units - item.used_units);
  }
  return null;
}

export function formatQuotaUnits(n: number): string {
  if (!Number.isFinite(n)) return "-";
  const abs = Math.abs(n);
  if (abs >= 1e8) return `${(n / 1e8).toFixed(2)} 亿`;
  if (abs >= 1e4) return `${(n / 1e4).toFixed(2)} 万`;
  return Math.round(n).toLocaleString();
}

export function computeGlm52PoolStats(
  profiles: ProfileView[],
  quotas: Record<string, QuotaInfo>,
  thresholdWan: number
): Glm52PoolStats {
  const thresholdUnits = thresholdWan * 10_000;
  let usedAccounts = 0;
  let usedUnits = 0;
  let rawTotalUnits = 0;
  let usedBelowThresholdUnits = 0;

  for (const profile of profiles) {
    const item = findGlm52Balance(quotas[profile.id]);
    if (!item) continue;

    const total = Number.isFinite(item.total_units) ? Math.max(0, item.total_units) : 0;
    const remaining = Number.isFinite(item.remaining_units)
      ? Math.max(0, item.remaining_units)
      : Math.max(0, total - (Number.isFinite(item.used_units) ? item.used_units : 0));
    const used = Number.isFinite(item.used_units)
      ? Math.max(0, item.used_units)
      : Math.max(0, total - remaining);

    rawTotalUnits += total;
    usedUnits += used;

    if (remaining < thresholdUnits) {
      usedAccounts += 1;
      usedBelowThresholdUnits += thresholdUnits - remaining;
    }
  }

  const totalUnits = Math.max(
    usedUnits,
    rawTotalUnits - profiles.length * thresholdUnits + usedBelowThresholdUnits
  );

  return {
    totalAccounts: profiles.length,
    usedAccounts,
    remainingAccounts: Math.max(0, profiles.length - usedAccounts),
    usedUnits,
    totalUnits,
  };
}
