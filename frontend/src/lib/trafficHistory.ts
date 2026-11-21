export type JournalKind = 'connection' | 'kill_switch' | 'quic' | 'error'

export type JournalLocation = {
    kind: 'server' | 'direct' | 'reject' | 'unresolved' | 'unknown'
    name?: string
    country?: string
    source?: string
}

export type JournalEntry = {
    id: string
    at: string
    kind: JournalKind
    device_id?: string
    device: string
    device_name?: string
    service_id?: string
    host: string
    port?: string
    network?: string
    route: string[]
    rule?: string
    exit?: JournalLocation
    count?: number
}

export type HistoryStorage = {
    id: string
    label: string
    mount_path: string
    free_bytes: number
    total_bytes: number
    available: boolean
    suggested_path: string
    reason?: string
}

export type HistorySettings = {
    supported?: boolean
    enabled: boolean
    running: boolean
    path: string
    storage_id: string
    storage_label?: string
    storage_available: boolean
    retention_hours: number
    max_events: number
    max_device_events: number
    max_bytes: number
    events: number
    bytes: number
    dropped: number
    queued: number
    oldest_at?: string
    latest_at?: string
    error?: string
    storages?: HistoryStorage[]
    memory_available_bytes?: number
    // The short journal the router keeps in memory.
    recent_enabled?: boolean
    recent_events?: number
    recent_count?: number
    recent_minutes?: number
    recent_oldest_at?: string
}

export type HistoryPage = {
    events: JournalEntry[]
    next_cursor?: string
    has_more: boolean
    status?: Partial<HistorySettings>
    devices?: { id: string; name?: string; ip?: string }[]
}

export const historySettingsKey = ['traffic-history-settings']
export const historySettingsPath = '/api/traffic-history/settings'

export function formatHistoryBytes(bytes?: number) {
    if (!Number.isFinite(bytes) || bytes == null || bytes < 0) return '—'
    const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ']
    const level = Math.min(units.length - 1, Math.floor(Math.log(Math.max(1, bytes)) / Math.log(1024)))
    return new Intl.NumberFormat('ru-RU', { maximumFractionDigits: level ? 1 : 0 }).format(bytes / 1024 ** level) + ' ' + units[level]
}
