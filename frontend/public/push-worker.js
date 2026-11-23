// Push-only worker. Authenticated pages and API responses are never cached.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()))
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()))

const notices = {
    server: ['Смена VPN-сервера', 'Изменился сервер для остальных сайтов.', '/servers'],
    update: ['Обновление панели', 'Доступна новая версия XKeen.', '/settings/update'],
    offline: ['VPN не работает', 'VPN не отвечает больше 2 минут.', '/'],
    online: ['VPN снова работает', 'Связь через VPN восстановилась.', '/'],
    kill_switch: ['Запрос остановлен защитой VPN', 'Не удалось использовать выбранный VPN. Прямой выход запрещён. Подробности — в журнале.', '/journal?kind=kill_switch'],
    test: ['Проверка уведомлений', 'XKeen может присылать события на это устройство.', '/settings/notifications'],
}
self.addEventListener('push', event => {
    let payload
    try { payload = event.data?.json() } catch {}
    const kind = payload?.kind
    const info = Object.hasOwn(notices, kind) ? notices[kind] : ['XKeen', 'Откройте панель для просмотра события.', '/']
    const version = typeof payload?.version === 'string' && /^v?\d[\w.+-]{0,63}$/.test(payload.version) ? payload.version : ''
    event.waitUntil(self.registration.showNotification(info[0], {
        body: kind === 'update' && version ? 'Доступна версия XKeen ' + version + '.' : info[1],
        icon: '/icon-192.png', tag: 'xkeen-' + (kind === 'online' || kind === 'offline' ? 'health' : kind),
        data: { path: info[2] },
    }))
})
self.addEventListener('notificationclick', event => {
    event.notification.close()
    const path = event.notification.data?.path
    const url = new URL(Object.values(notices).some(item => item[2] === path) ? path : '/', self.location.origin)
    event.waitUntil((async () => {
        const tabs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
        const tab = tabs.find(client => new URL(client.url).origin === self.location.origin)
        if (tab) {
            const routed = await tab.navigate(url.href)
            if (routed) return routed.focus()
        }
        return self.clients.openWindow(url.href)
    })())
})
