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

// «Без страны» among the excluded locations: ZZ, the code of an unknown region.
export const NO_COUNTRY = 'ZZ'

export function locationLabel(code: string) {
    return code === NO_COUNTRY ? 'Без страны' : countryLabel(code)
}

export function locationName(code: string) {
    return code === NO_COUNTRY ? 'Без страны' : countryName(code)
}

// Whether automatic choice skips a server of this location; a server without
// one is skipped when «Без страны» is excluded.
export function locationExcluded(avoid: string[], code?: string) {
    return avoid.includes((code || NO_COUNTRY).toUpperCase())
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

// "только что", "5 мин назад": timeAgo with the word that only a duration takes.
export function agoLabel(iso?: string) {
    const ago = timeAgo(iso)
    return ago && ago !== 'только что' ? ago + ' назад' : ago
}

// Russian plural: plural(4, 'запись', 'записи', 'записей') gives "записи".
export function plural(n: number, one: string, few: string, many: string) {
    const tens = Math.abs(n) % 100, units = tens % 10
    if (tens > 10 && tens < 20) return many
    if (units === 1) return one
    return units >= 2 && units <= 4 ? few : many
}

export type Tone = 'good' | 'warn' | 'bad' | 'idle'

export type StatusInfo = { label: string; tone: Tone; detail?: string }

// One vocabulary for every screen. killSwitch is the global kill switch when
// known: it decides whether a dead VPN pauses the internet or lets it out directly.
export function statusInfo(s?: Status, killSwitch?: boolean): StatusInfo {
    if (!s) return { label: 'Загрузка', tone: 'idle' }
    if (s.restarting) return { label: 'Перезапуск', tone: 'warn' }
    if (s.process_unknown) return { label: 'Состояние ядра неизвестно', tone: 'warn' }
    if (!s.xray_running) return { label: 'VPN остановлен', tone: 'bad', detail: 'Ядро XKeen не запущено.' }
    if (!isSet(s.last_check)) return { label: 'Проверяю', tone: 'idle' }
    const vpn = s.selective ? 'VPN для Re:filter' : 'VPN'
    if (s.core === 'mihomo' && !s.proxy_checked) {
        if (s.current_server === 'DIRECT') return s.selective
            ? { label: 'Re:filter напрямую', tone: 'warn', detail: 'Для адресов из Re:filter выбран прямой выход.' }
            : { label: 'Напрямую', tone: 'idle', detail: 'Остальные сайты открываются без VPN.' }
        if (s.current_server === 'REJECT') return { label: 'Заблокировано', tone: 'warn', detail: s.selective ? 'Адреса из Re:filter заблокированы.' : 'Остальные сайты заблокированы.' }
        return { label: 'Проверка VPN недоступна', tone: 'warn' }
    }
    if (s.connected && s.proxy_checked) return { label: vpn + ' работает', tone: 'good' }
    if (s.connected) return { label: 'Не подтверждено', tone: 'warn' }
    if (!s.internet) return { label: 'Нет интернета у провайдера', tone: 'bad', detail: 'Роутер не выходит в интернет даже напрямую — VPN тут ни при чём.' }
    if (s.searching) return { label: vpn + ' ищет сервер', tone: 'warn', detail: 'Сервер автовыбора не ответил — панель проверяет остальные серверы пула.' }
    const paused = s.held || killSwitch === true
    const detail = s.selective
        ? paused ? 'Адреса из Re:filter не открываются: kill switch не выпускает их напрямую.' : undefined
        : paused ? 'Интернет приостановлен: kill switch не выпускает трафик напрямую.'
            : killSwitch === false ? 'Трафик идёт напрямую, с домашнего адреса.' : undefined
    return { label: vpn + ' не работает', tone: 'bad', detail }
}

// The cards whose own VPN route stopped answering.
export function routesDownText(s?: Status) {
    const names = s?.routes_down ?? []
    return names.length ? `Не отвечает VPN: ${names.join(', ')}` : ''
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

// <200 ms green, 200–499 orange, slower or no answer red; 0 is not measured yet.
export function latencyTone(ms: number): Tone {
    if (ms < 0) return 'bad'
    if (ms === 0) return 'idle'
    if (ms < 200) return 'good'
    if (ms < 500) return 'warn'
    return 'bad'
}
