import type { Status, UpdateState } from '@/types'
import { useEffect } from 'react'
import { api } from '@/lib/api'

export type Preferences = { server: boolean; update: boolean; health: boolean; kill_switch: boolean }
export const defaultPreferences: Preferences = { server: true, update: true, health: true, kill_switch: true }
export const preferenceKey = 'xkeen.notifications.tab.v1'
const draftPrefsKey = 'xkeen.notifications.preferences.v1'
const baselineKey = 'xkeen.notifications.last.v1'

// Fallback for browsers with Notifications but without usable Web Push.
// Scope the subscription to this browser profile and share the baseline across tabs.
function readPreferences(key: string): Preferences | null {
    try {
        const saved = JSON.parse(localStorage.getItem(key) || 'null')
        return saved && ['server', 'update', 'health'].every(field => typeof saved[field] === 'boolean') ?
            { server: saved.server, update: saved.update, health: saved.health, kill_switch: saved.kill_switch === true } : null
    } catch { return null }
}
export const tabPreferences = () => readPreferences(preferenceKey)
export const savedPreferences = () => readPreferences(draftPrefsKey) ?? defaultPreferences
export const savePreferences = (p: Preferences) => localStorage.setItem(draftPrefsKey, JSON.stringify(p))
export function setTabPreferences(p: Preferences | null) {
    if (p) localStorage.setItem(preferenceKey, JSON.stringify(p))
    else localStorage.removeItem(preferenceKey)
    if (!p) localStorage.removeItem(baselineKey)
}

type Baseline = { route?: string; connected?: boolean; down_since?: number; version?: string; guard?: string; guard_notice_at?: number }

// An outage is announced once it lasted this long: a short pause, such as the
// router switching servers, is not worth a notification.
const outageNotice = 120000
function baseline(): Baseline {
    try { return JSON.parse(localStorage.getItem(baselineKey) || '{}') || {} } catch { return {} }
}

export async function tabNotice(title: string, body: string, path: string, tag: string) {
    const options = { body, icon: '/icon-192.png', tag: 'xkeen-' + tag, data: { path } }
    const sw = 'serviceWorker' in navigator ? await navigator.serviceWorker.getRegistration('/') : undefined
    if (sw?.active?.scriptURL === new URL('/push-worker.js', location.origin).href) {
        await sw.showNotification(title, options)
        return
    }
    const notice = new Notification(title, options)
    notice.onclick = () => { window.focus(); window.location.assign(path); notice.close() }
}

export function observeTabNotification(status?: Status, update?: UpdateState) {
    const prefs = tabPreferences()
    if (!prefs || !('Notification' in window) || Notification.permission !== 'granted') return
    const last = baseline()
    const send = (title: string, body: string, path: string, tag: string) => {
        void tabNotice(title, body, path, tag).catch(() => {})
    }
    if (status && !status.restarting) {
        const route = [status.current_server,status.protocol].join('|')
        if (status.current_server) {
            if (prefs.server && last.route && last.route !== route) send('Смена VPN-сервера', 'Изменился сервер для остальных сайтов.', '/servers', 'server')
            last.route = route
        }
        if (status.proxy_checked && Date.parse(status.last_check) > 0) {
            // last.connected is the state the owner was last told about.
            if (status.connected) {
                if (prefs.health && last.connected === false) send('VPN снова работает', 'Связь через VPN восстановилась.', '/', 'health')
                last.connected = true
                delete last.down_since
            } else {
                last.down_since ??= Date.now()
                if (last.connected !== false && Date.now() - last.down_since >= outageNotice) {
                    if (prefs.health) send('VPN не работает', 'VPN не отвечает больше 2 минут.', '/', 'health')
                    last.connected = false
                }
            }
        }
    }
    if (prefs.update && update?.available && update.latest?.tag && last.version !== update.latest.tag) {
        send('Обновление панели', 'Доступна версия XKeen ' + update.latest.tag + '.', '/settings/update', 'update')
        last.version = update.latest.tag
    }
    localStorage.setItem(baselineKey, JSON.stringify(last))
}

type GuardNotice = { id: string; at: string; reason: string }
export function observeTabGuard(events: GuardNotice[]) {
    const prefs = tabPreferences()
    if (!prefs?.kill_switch || !('Notification' in window) || Notification.permission !== 'granted') return
    const event = events.find(event => event.reason !== 'protocol_guard')
    if (!event || Date.now() - Date.parse(event.at) > 120000) return
    const last = baseline()
    if (last.guard === event.id) return
    last.guard = event.id
    const send = !last.guard_notice_at || Date.now() - last.guard_notice_at >= 60000
    if (send) last.guard_notice_at = Date.now()
    localStorage.setItem(baselineKey, JSON.stringify(last))
    if (send) void tabNotice('Запрос остановлен защитой VPN',
        'Не удалось использовать выбранный VPN. Прямой выход запрещён. Подробности — в журнале.',
        '/journal?kind=kill_switch', 'kill_switch').catch(() => {})
}

// Tab-only notifications work on every panel page. This reads a small local
// in-memory journal and adds no probes or requests through user VPN routes.
export function useGuardNotifications() {
    useEffect(() => {
        let stopped = false
        let pending = false
        const read = async () => {
            if (stopped || pending || !tabPreferences()?.kill_switch) return
            pending = true
            try {
                const data = await api.get<{ events: GuardNotice[] }>('/api/kill-switch/events')
                if (!stopped) observeTabGuard(data.events)
            } catch { /* The diagnostics page reports an unavailable observer. */ }
            finally { pending = false }
        }
        void read()
        const timer = window.setInterval(() => { void read() }, 10000)
        return () => { stopped = true; window.clearInterval(timer) }
    }, [])
}

export async function pushID(sub: PushSubscription): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sub.endpoint))
    return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('')
}

export function decodePushKey(key: string): Uint8Array<ArrayBuffer> {
    const base = key.replace(/-/g, '+').replace(/_/g, '/')
    return Uint8Array.from(atob(base.padEnd(base.length + (4 - base.length % 4) % 4, '=')), char => char.charCodeAt(0))
}

