import type { AutoScope, Server, Status } from '@/types'

const regions = new Intl.DisplayNames(['ru'], { type: 'region' })

export function countryName(code?: string) {
    if (!code || code.length !== 2) return ''
    try {
        return regions.of(code.toUpperCase()) ?? code
    } catch {
        return code
    }
}

export function countryFlag(code?: string) {
    const upper = code?.toUpperCase()
    if (!upper || !/^[A-Z]{2}$/.test(upper)) return ''
    return String.fromCodePoint(...Array.from(upper, letter => 0x1F1E6 + letter.charCodeAt(0) - 65))
}

export function countryLabel(code?: string) {
    return [countryFlag(code), countryName(code)].filter(Boolean).join(' ')
}

export function withCountryFlag(name: string, code?: string) {
    const flag = countryFlag(code)
    return flag && !/\p{Regional_Indicator}{2}/u.test(name) ? flag + ' ' + name : name
}

export function scopeLabel(scope: { kind: string; country?: string; name: string }) {
    if (scope.kind === 'all') return 'Все локации'
    if (scope.kind === 'country' && scope.country) return countryLabel(scope.country)
    return scope.name
}

export function unavailableCountryReason(scope: AutoScope, avoided: string[]) {
    switch (scope.unavailable_reason) {
        case 'country_filter': return scope.country && avoided.includes(scope.country)
            ? 'страна исключена в настройках' : 'нет подходящих серверов'
        case 'unsupported': return 'нет совместимых серверов'
        case 'no_servers': return 'больше нет в подписках'
        default: return 'нет подходящих серверов'
    }
}

export function serverCountry(server?: Server) {
    return (server?.country_override || server?.country || '').toUpperCase()
}

// Go marshals an unset time as year 1
export function isSet(iso?: string) {
    return !!iso && !iso.startsWith('0001')
}

export function timeAgo(iso?: string) {
    if (!isSet(iso)) return ''
    const minutes = Math.round((Date.now() - new Date(iso!).getTime()) / 60000)
    if (minutes < 1) return 'только что'
    if (minutes < 60) return `${minutes} мин`
    const hours = Math.round(minutes / 60)
    if (hours < 24) return `${hours} ч`
    return `${Math.round(hours / 24)} дн`
}

export type Tone = 'good' | 'warn' | 'bad' | 'idle'

export function statusInfo(s?: Status): { label: string; tone: Tone } {
    if (!s) return { label: 'Загрузка', tone: 'idle' }
    if (s.restarting) return { label: 'Перезапуск', tone: 'warn' }
    if (s.process_unknown) return { label: 'Состояние ядра неизвестно', tone: 'warn' }
    if (!s.xray_running) return { label: 'Прокси остановлен', tone: 'bad' }
    if (!isSet(s.last_check)) return { label: 'Проверяю', tone: 'idle' }
    if (s.core === 'mihomo' && !s.proxy_checked) {
        if (s.current_server === 'DIRECT') return { label: s.selective ? 'Для списка выбран прямой выход' : 'Основной маршрут напрямую', tone: s.selective ? 'warn' : 'idle' }
        if (s.current_server === 'REJECT') return { label: s.selective ? 'Маршрут для списка заблокирован' : 'Основной маршрут заблокирован', tone: 'warn' }
        return { label: 'Проверка маршрута недоступна', tone: 'warn' }
    }
    if (s.connected && s.proxy_checked)
        return { label: s.selective ? 'VPN для списка работает' : 'VPN-маршрут работает', tone: 'good' }
    if (s.connected) return { label: 'Не подтверждено', tone: 'warn' }
    if (!s.internet) return { label: 'Нет интернета', tone: 'bad' }
    return { label: s.selective ? 'VPN для списка не отвечает' : 'Основной маршрут не отвечает', tone: 'bad' }
}

export const toneText: Record<Tone, string> = {
    good: 'text-success',
    warn: 'text-warning',
    bad: 'text-destructive',
    idle: 'text-muted-foreground',
}

export const toneFill: Record<Tone, string> = {
    good: 'bg-success/15',
    warn: 'bg-warning/15',
    bad: 'bg-destructive/15',
    idle: 'bg-fill',
}

export const toneDot: Record<Tone, string> = {
    good: 'bg-success',
    warn: 'bg-warning',
    bad: 'bg-destructive',
    idle: 'bg-muted-foreground',
}

export type PanelEvent = { time: string; text: string }

const routine = [
    /\[OK\]/,
    /Watchdog (запущен|остановлен)/,
    /\[HEALTH\] https?:/,
    /\[WARN\]/,
]

// The panel log doubles as an event feed once routine heartbeat lines are dropped
export function panelEvents(lines: string[], limit: number): PanelEvent[] {
    const events: PanelEvent[] = []
    for (let i = lines.length - 1; i >= 0 && events.length < limit; i--) {
        const line = lines[i]
        if (routine.some(re => re.test(line))) continue
        const m = line.match(
            /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}):\d{2} (?:\[[^\]]+\] )?(.*)$/,
        )
        if (!m) continue
        const today = new Date().toISOString().slice(0, 10) === m[1]
        const day = today
            ? ''
            : new Date(m[1]).toLocaleDateString('ru-RU', {
                  day: 'numeric',
                  month: 'short',
              }) + ' '
        const text = m[3]
            .replace(/\s*\((manual|sub-\d+)\)/g, '')
            .replace(/:\s*(manual|sub-\d+)$/, '')
        events.push({ time: day + m[2], text })
    }
    return events
}

export function latencyTone(ms: number): Tone {
    if (ms < 0) return 'bad'
    if (ms < 200) return 'idle'
    if (ms < 500) return 'warn'
    return 'bad'
}
