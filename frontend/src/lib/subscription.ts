import type { ImportReport, ServerSource, SubscriptionUsage } from '@/types'
import { plural } from '@/lib/format'

const day = 24 * 60 * 60 * 1000

export function formatBytes(bytes: number) {
    const gb = bytes / 1024 ** 3
    if (gb >= 1) return `${gb.toLocaleString('ru-RU', { maximumFractionDigits: gb < 10 ? 1 : 0 })} ГБ`
    return `${Math.max(0, Math.round(bytes / 1024 ** 2)).toLocaleString('ru-RU')} МБ`
}

// What the provider reported: "Осталось 12,4 ГБ из 50 ГБ · до 12 дек.".
export function usageText(usage?: SubscriptionUsage) {
    if (!usage) return ''
    const parts: string[] = []
    const used = (usage.upload ?? 0) + (usage.download ?? 0)
    if (usage.total && usage.total > 0) parts.push(`Осталось ${formatBytes(Math.max(0, usage.total - used))} из ${formatBytes(usage.total)}`)
    else if (used > 0) parts.push(`Израсходовано ${formatBytes(used)}`)
    if (usage.expire && usage.expire > 0) {
        const end = new Date(usage.expire * 1000)
        parts.push(end.getTime() < Date.now() ? 'срок закончился' : 'до ' + end.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short', year: end.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' }))
    }
    return parts.join(' · ')
}

// Warnings three days before the end and when 10% of the traffic is left.
export function usageWarnings(sources: ServerSource[]) {
    const out: string[] = []
    for (const source of sources) {
        const usage = source.usage
        if (!usage) continue
        if (usage.expire && usage.expire > 0) {
            const left = usage.expire * 1000 - Date.now()
            if (left <= 0) out.push(`${source.name}: срок подписки закончился`)
            else if (left <= 3 * day) {
                const days = Math.ceil(left / day)
                out.push(`${source.name}: подписка закончится через ${days} ${plural(days, 'день', 'дня', 'дней')}`)
            }
        }
        const used = (usage.upload ?? 0) + (usage.download ?? 0)
        if (usage.total && usage.total > 0) {
            const left = usage.total - used
            if (left <= 0) out.push(`${source.name}: трафик подписки закончился`)
            else if (left <= usage.total / 10) out.push(`${source.name}: осталось ${formatBytes(left)} трафика`)
        }
    }
    return out
}

// Subscription/API diagnostics must never reflect credentials into the UI.
export function safeNotice(value: unknown, fallback: string): string {
    if (typeof value !== 'string' || !value.trim()) return fallback
    if (
        /[a-z][a-z0-9+.-]*:\/\//i.test(value) ||
        /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.test(
            value,
        ) ||
        /[A-Za-z0-9_=-]{48,}/.test(value)
    )
        return fallback
    return value.slice(0, 500)
}

export function importWarnings(
    report?: ImportReport,
    warnings?: string[],
): string[] {
    const values = report?.warnings ?? warnings ?? []
    if (values.length > 0) {
        return [
            ...new Set(
                values.map(value =>
                    safeNotice(value, 'Некоторые профили подписки пропущены.'),
                ),
            ),
        ]
    }
    if ((report?.skipped_composite ?? 0) > 0) {
        return [
            'Составные режимы пропущены; самостоятельные серверы доступны в списке.',
        ]
    }
    return []
}
