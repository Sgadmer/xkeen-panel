import { useEffect, useState } from 'react'
import { Group, PageTitle, Row, Switch } from '@/components/ios'
import { api } from '@/lib/api'
import {
    decodePushKey, savedPreferences, savePreferences, pushID, setTabPreferences,
    tabNotice, tabPreferences, type Preferences,
} from '@/lib/notifications'

type Mode = 'off' | 'push' | 'tab'
type DeviceState = { enabled: boolean; preferences: Preferences }
type PushSetup = { worker: ServiceWorkerRegistration; key: Uint8Array<ArrayBuffer> }
const events: { key: keyof Preferences; label: string; hint: string }[] = [
    { key: 'server', label: 'Смена сервера', hint: 'Изменился сервер общего маршрута' },
    { key: 'update', label: 'Обновление панели', hint: 'Появилась новая версия панели' },
    { key: 'health', label: 'Связь через VPN', hint: 'Общий маршрут перестал отвечать или восстановился' },
]
const browserSubscription = async () => {
    if (!('serviceWorker' in navigator)) return null
    const reg = await navigator.serviceWorker.getRegistration('/')
    return await reg?.pushManager?.getSubscription() ?? null
}
const storedIDKey = 'xkeen.notifications.device.v1'

async function preparePush(): Promise<PushSetup> {
    await navigator.serviceWorker.register('/push-worker.js')
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
        const ready = Promise.race([
            navigator.serviceWorker.ready,
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error('Браузер не запустил службу уведомлений.')), 15000)
            }),
        ])
        const [worker, { key }] = await Promise.all([ready, api.get<{ key: string }>('/api/notifications/key')])
        return { worker, key: decodePushKey(key) }
    } finally {
        clearTimeout(timer)
    }
}

export function NotificationsPage() {
    const available = window.isSecureContext && 'Notification' in window
    const pushSupported = available && 'serviceWorker' in navigator && 'PushManager' in window
    const onIPhone = /iPhone|iPad|iPod/i.test(navigator.userAgent) || navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1
    const standalone = window.matchMedia('(display-mode: standalone)').matches || (navigator as Navigator & { standalone?: boolean }).standalone === true
    const [permission, setPermission] = useState(() => available ? Notification.permission : 'default')
    const [prefs, setPrefs] = useState<Preferences>(() => tabPreferences() ?? savedPreferences())
    const [mode, setMode] = useState<Mode>(() => tabPreferences() ? 'tab' : 'off')
    const [sub, setSub] = useState<PushSubscription | null>(null)
    const [setup, setSetup] = useState<PushSetup | null>(null)
    const [busy, setBusy] = useState(true)
    const [feedback, setFeedback] = useState('')
    const [fallback, setFallback] = useState(false)
    const [remoteKnown, setRemoteKnown] = useState(false)
    const [retry, setRetry] = useState(0)
    const [staleID, setStaleID] = useState<string | null>(null)
    useEffect(() => {
        let live = true
        async function load() {
            const current = pushSupported ? await browserSubscription() : null
            const savedID = localStorage.getItem(storedIDKey)
            const id = current ? await pushID(current) : savedID
            const state = id ? await api.post<DeviceState>('/api/notifications/status', { id }) : null
            if (!live) return
            setSub(current)
            setStaleID(savedID && (!current || savedID !== id) ? savedID : null)
            if (state?.enabled && current) {
                setTabPreferences(null)
                setMode('push')
                setPrefs(state.preferences)
                savePreferences(state.preferences)
                if (!savedID) localStorage.setItem(storedIDKey, id!)
            } else {
                const local = tabPreferences()
                setMode(local ? 'tab' : 'off')
                setPrefs(local ?? savedPreferences())
            }
            setRemoteKnown(true)
            if (pushSupported && (!onIPhone || standalone) && Notification.permission !== 'denied') {
                try {
                    const ready = await preparePush()
                    if (live) { setSetup(ready); setFallback(false) }
                } catch {
                    if (live) {
                        setSetup(null)
                        setFallback(true)
                        setFeedback('Не удалось подготовить фоновую доставку.')
                    }
                }
            }
        }
        setRemoteKnown(false)
        setBusy(true)
        void load().catch(() => { if (live) setFeedback('Не удалось прочитать подписку устройства.') })
            .finally(() => { if (live) setBusy(false) })
        const sync = () => {
            if (available && live) setPermission(Notification.permission)
        }
        window.addEventListener('focus', sync)
        return () => {
            live = false
            window.removeEventListener('focus', sync)
        }
    }, [available, pushSupported, onIPhone, standalone, retry])

    async function run(action: () => Promise<void>) {
        setBusy(true)
        setFeedback('')
        try { await action() }
        catch (error) { setFeedback(error instanceof Error ? error.message : 'Операция с уведомлениями не завершена.') }
        finally { setBusy(false) }
    }

    async function removeStaleID() {
        if (staleID) {
            await api.del('/api/notifications/device',{ id: staleID })
            localStorage.removeItem(storedIDKey)
            setStaleID(null)
        }
    }

    async function enable(tabOnly = false) {
        if (tabOnly || !pushSupported) {
            const granted = await Notification.requestPermission()
            setPermission(granted)
            if (granted !== 'granted') {
                setFeedback('Уведомления включатся после разрешения в настройках браузера.')
                return
            }
            await removeStaleID()
            setTabPreferences(prefs)
            setMode('tab')
            setFallback(false)
            return
        }
        if (!setup) throw new Error('Повторите подготовку фоновой доставки.')
        if (sub) {
            // The server no longer recognizes this browser endpoint. Safari needs
            // a fresh tap to subscribe after asynchronous revocation completes.
            await api.del('/api/notifications/device', { id: await pushID(sub) })
            await sub.unsubscribe()
            setSub(null)
            localStorage.removeItem(storedIDKey)
            setFeedback('Старая подписка устройства удалена. Включите уведомления ещё раз.')
            return
        }
        let current: PushSubscription
        try {
            // Invoke subscribe directly from the tap, before the first await.
            // This call shows the platform permission prompt when needed.
            current = await setup.worker.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: setup.key })
            setPermission(Notification.permission)
            setSub(current)
            await removeStaleID()
            await api.put('/api/notifications/device', { subscription: current.toJSON(), preferences: prefs })
        } catch (error) {
            setPermission(Notification.permission)
            setFallback(true)
            throw new Error(error instanceof Error ? 'Фоновая доставка недоступна. ' + error.message : 'Фоновая доставка недоступна.')
        }
        localStorage.setItem(storedIDKey, await pushID(current))
        setTabPreferences(null)
        setMode('push')
        setFallback(false)
    }
    async function disable() {
        const id = sub ? await pushID(sub) : localStorage.getItem(storedIDKey)
        if (id) await api.del('/api/notifications/device', { id })
        if (staleID && staleID !== id) await api.del('/api/notifications/device', { id: staleID })
        setTabPreferences(null)
        localStorage.removeItem(storedIDKey)
        setMode('off')
        setStaleID(null)
        setFallback(false)
        if (sub) {
            await sub.unsubscribe()
            setSub(null)
        }
    }
    async function choose(key: keyof Preferences, value: boolean) {
        const next = { ...prefs, [key]: value }
        if (mode === 'push' && sub) await api.put('/api/notifications/device', { subscription: sub.toJSON(), preferences: next })
        if (mode === 'tab') setTabPreferences(next)
        savePreferences(next)
        setPrefs(next)
    }
    async function test() {
        if (mode === 'push' && sub) {
            try {
                await api.post('/api/notifications/test', { id: await pushID(sub) })
            } catch (error) {
                if (error instanceof Error && 'status' in error && error.status === 410) {
                    await sub.unsubscribe()
                    setSub(null)
                    setMode('off')
                    localStorage.removeItem(storedIDKey)
                }
                throw error
            }
            setFeedback('Служба Web Push приняла проверочное уведомление.')
        } else {
            await tabNotice('Проверка уведомлений', 'XKeen может показывать события в открытой панели.', '/settings/notifications', 'test')
            setFeedback('Проверочное уведомление передано браузеру.')
        }
    }
    const blocked = !available || permission === 'denied' || onIPhone && !standalone
    let hint = mode === 'push' ? 'Фоновая доставка через службу Web Push браузера, включая закрытую вкладку.' :
        mode === 'tab' ? 'Уведомления приходят, пока панель открыта в этом браузере.' :
        'Разрешить системные уведомления от панели в этом браузере.'
    if (!window.isSecureContext) hint='Откройте HTTPS-адрес панели в домашней сети.'
    else if (onIPhone && !standalone) hint='На iPhone добавьте HTTPS-панель на экран «Домой» из меню «Поделиться» в Safari и откройте её со значка. Требуется iOS 16.4 или новее.'
    else if (!available) hint='Этот браузер не поддерживает системные уведомления сайта.'
    else if (permission === 'denied') hint='Откройте разрешения этого сайта в браузере и разрешите уведомления.'
    else if (mode === 'off' && !pushSupported) hint='Браузер может показывать уведомления, пока вкладка панели открыта.'

    return <>
        <PageTitle title='Уведомления' subtitle='Для этого браузера и устройства' back={{to:'/settings',label:'Настройки'}} />
        <Group title='Доставка'>
            <Row label='Системные уведомления' hint={hint} trailing={
                <Switch label='Системные уведомления' checked={mode !== 'off' && permission === 'granted'} disabled={busy || !remoteKnown || mode === 'off' && (blocked || (pushSupported && !setup))}
                    onChange={enabled => { void run(enabled && !blocked ? () => enable() : disable) }} />
            } />
            {!remoteKnown && !busy && <Row label='Повторить проверку' tone='tint' onClick={() => setRetry(x => x + 1)} />}
            {fallback && !setup && !blocked && <Row label='Повторить подготовку Web Push' disabled={busy} onClick={() => setRetry(x => x + 1)} />}
            {mode === 'push' && blocked && <Row label='Отключить подписку устройства' disabled={busy} onClick={() => {void run(disable)}} />}
            {fallback && mode === 'off' && !blocked && <Row label='Уведомлять в открытой панели' tone='tint' disabled={busy} onClick={() => {void run(() => enable(true))}} />}
            {mode === 'tab' && setup && !blocked && <Row label='Включить фоновую доставку' tone='tint' disabled={busy} onClick={() => {void run(() => enable())}} />}
            {mode !== 'off' && !blocked && <Row label='Отправить проверочное уведомление' tone='tint' disabled={busy} onClick={() => {void run(test)}} />}
        </Group>
        {feedback && <p className='px-4 text-sm text-foreground' role='status'>{feedback}</p>}
        <Group title='Какие события присылать'>
            {events.map(({key,label,hint})=><Row key={key} label={label} hint={hint} trailing={
                <Switch label={label} checked={prefs[key]} disabled={busy || blocked || !remoteKnown}
                    onChange={value => {void run(() => choose(key,value))}} />
            } />)}
        </Group>
    </>
}

