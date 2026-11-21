import type { JournalKind } from '@/lib/trafficHistory'

// Where the records come from: connections open right now, the short journal
// the router keeps in memory, or the day-long journal on an external disk.
export type JournalSource = 'live' | 'recent' | 'history'
export type JournalView = 'list' | 'sites'

export type JournalFilters = {
    source: JournalSource
    view: JournalView
    device: string
    service: string
    kind: JournalKind | ''
    search: string
}

export type JournalPreset = Partial<Omit<JournalFilters, 'source' | 'view'>> & {
    id: string
    name: string
    source: JournalSource
    view: JournalView
}

export type JournalSite = {
    host: string
    service_id?: string
    count: number
    vpn: number
    direct: number
    blocked: number
    errors: number
    last_at: string
    exit?: string
    devices: number
}

export const defaultFilters: JournalFilters = { source: 'recent', view: 'list', device: '', service: '', kind: '', search: '' }

const sources: JournalSource[] = ['live', 'recent', 'history']
const kinds: (JournalKind | '')[] = ['', 'connection', 'kill_switch', 'quic', 'error']
const STORE = 'xkeen.journal.filters.v1'

export function filtersFromParams(params: URLSearchParams): JournalFilters {
    const source = params.get('src') as JournalSource
    const kind = (params.get('kind') ?? '') as JournalKind | ''
    const filters: JournalFilters = {
        source: sources.includes(source) ? source : defaultFilters.source,
        view: params.get('view') === 'sites' ? 'sites' : 'list',
        device: params.get('device') ?? '',
        service: params.get('service') ?? '',
        kind: kinds.includes(kind) ? kind : '',
        search: params.get('q') ?? '',
    }
    // The grouped view exists for the short journal only.
    if (filters.view === 'sites') filters.source = 'recent'
    return filters
}

export function paramsFromFilters(filters: JournalFilters): URLSearchParams {
    const params = new URLSearchParams()
    if (filters.source !== defaultFilters.source) params.set('src', filters.source)
    if (filters.view !== 'list') params.set('view', filters.view)
    if (filters.device) params.set('device', filters.device)
    if (filters.service) params.set('service', filters.service)
    if (filters.kind) params.set('kind', filters.kind)
    if (filters.search.trim()) params.set('q', filters.search.trim())
    return params
}

// The journal opens the way it was left, on this device.
export function rememberedFilters(): JournalFilters | null {
    try {
        const raw = localStorage.getItem(STORE)
        return raw ? filtersFromParams(new URLSearchParams(raw)) : null
    } catch {
        return null
    }
}

export function rememberFilters(filters: JournalFilters) {
    try {
        localStorage.setItem(STORE, paramsFromFilters(filters).toString())
    } catch {
        // Private mode: the filters still live in the address of the page.
    }
}

export function sameFilters(a: JournalFilters, b: Partial<JournalFilters>) {
    return a.source === (b.source ?? defaultFilters.source) && a.view === (b.view ?? 'list') && a.device === (b.device ?? '') &&
        a.service === (b.service ?? '') && a.kind === (b.kind ?? '') && a.search.trim() === (b.search ?? '').trim()
}

// What goes to the router for the short and the day-long journal.
export function historyQuery(filters: JournalFilters, limit: number, window?: { since?: string; before?: string }) {
    const query = new URLSearchParams({ limit: String(limit) })
    if (filters.source === 'recent') query.set('source', 'recent')
    if (filters.device) query.set('device', filters.device)
    if (filters.service) query.set('service', filters.service)
    if (filters.kind) query.set('kind', filters.kind)
    if (filters.search.trim()) query.set('q', filters.search.trim())
    if (window?.since) query.set('since', window.since)
    if (window?.before) query.set('before', window.before)
    return query.toString()
}

export function saveTextFile(name: string, text: string) {
    const link = document.createElement('a')
    link.href = URL.createObjectURL(new Blob(['﻿' + text], { type: 'text/tab-separated-values;charset=utf-8' }))
    link.download = name
    document.body.append(link)
    link.click()
    link.remove()
    setTimeout(() => URL.revokeObjectURL(link.href), 1000)
}
