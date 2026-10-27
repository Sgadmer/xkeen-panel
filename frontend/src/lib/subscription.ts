import type { ImportReport } from '@/types'

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
