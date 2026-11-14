import type { Status, UpdateState } from '@/types'

export type Preferences = { server: boolean; update: boolean; health: boolean }
export const defaultPreferences: Preferences = { server: true, update: true, health: true }
export const preferenceKey = 'xkeen.notifications.tab.v1'
const draftPrefsKey = 'xkeen.notifications.preferences.v1'
const baselineKey = 'xkeen.notifications.last.v1'

// Fallback for browsers with Notifications but without usable Web Push.
// Scope the subscription to this browser profile and share the baseline across tabs.
function readPreferences(key: string): Preferences | null {
    try {
        const saved = JSON.parse(localStorage.getItem(key) || 'null')
        return saved && ['server', 'update', 'health'].every(field => typeof saved[field] === 'boolean') ? saved : null
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

type Baseline = { route?: string; connected?: boolean; version?: string }
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
            if (prefs.server && last.route && last.route !== route) send('Смена VPN-сервера', 'Изменился сервер общего маршрута.', '/servers', 'server')
            last.route = route
        }
        if (status.proxy_checked && Date.parse(status.last_check) > 0) {
            if (prefs.health && last.connected !== status.connected && (last.connected !== undefined || !status.connected)) {
                send(status.connected ? 'VPN восстановлен' : 'VPN недоступен', status.connected ? 'Общий маршрут снова прошёл проверку.' : 'Проверка общего маршрута завершилась ошибкой.', '/diagnostics', 'health')
            }
            last.connected = status.connected
        }
    }
    if (prefs.update && update?.available && update.latest?.tag && last.version !== update.latest.tag) {
        send('Обновление панели', 'Доступна версия XKeen ' + update.latest.tag + '.', '/settings/update', 'update')
        last.version = update.latest.tag
    }
    localStorage.setItem(baselineKey, JSON.stringify(last))
}

export async function pushID(sub: PushSubscription): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sub.endpoint))
    return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('')
}

export function decodePushKey(key: string): Uint8Array<ArrayBuffer> {
    const base = key.replace(/-/g, '+').replace(/_/g, '/')
    return Uint8Array.from(atob(base.padEnd(base.length + (4 - base.length % 4) % 4, '=')), char => char.charCodeAt(0))
}

