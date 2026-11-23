import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { IconShieldCheckFilled } from '@tabler/icons-react'
import { Group, PageTitle, Row } from '@/components/ios'
import { serviceKillSwitch, useKillSwitch } from '@/components/killSwitch'
import { usePortsThroughVPN } from '@/components/protectionSummary'
import { usePanelSettings, useStatus } from '@/hooks/usePanelData'
import { aiServiceIds, isAiService } from '@/lib/aiServiceGroup'
import { api } from '@/lib/api'
import { historySettingsKey, historySettingsPath, type HistorySettings } from '@/lib/trafficHistory'

type Routes = { default_service_target?: string; services: { id: string; name: string; target: string; custom?: boolean }[] }
type Mode = { enabled: boolean; mode?: 'protected' | 'blocklist' | 'custom' }
type Dns = { mode: 'router' | 'secure'; foreign: boolean }
type Refilter = { supported: boolean; auto: boolean }

// One setting that differs from what the panel recommends.
type Item = {
    id: string
    group: 'Защита' | 'Автоматика' | 'Журнал и списки'
    title: string
    now: string
    advice: string
    restore?: () => Promise<unknown>
    link?: string
}

const REFRESH = 60

// What differs from the recommended settings, and one tap to put each back.
// Returning to a recommended value never lowers protection, so it asks nothing.
export function RecommendedPage() {
    const client = useQueryClient()
    const status = useStatus().data
    const mihomo = status?.core === 'mihomo'
    const policy = useKillSwitch(mihomo)
    const settings = usePanelSettings().data
    const routes = useQuery({ queryKey: ['service-routes'], queryFn: () => api.get<Routes>('/api/service-routes'), enabled: mihomo }).data
    const mode = useQuery({ queryKey: ['routing-blocklist'], queryFn: () => api.get<Mode>('/api/routing/blocklist'), enabled: mihomo }).data
    const dns = useQuery({ queryKey: ['mihomo-dns'], queryFn: () => api.get<Dns>('/api/dns'), enabled: mihomo }).data
    const refilter = useQuery({ queryKey: ['refilter-files'], queryFn: () => api.get<Refilter>('/api/components/refilter'), enabled: mihomo }).data
    const journal = useQuery({ queryKey: historySettingsKey, queryFn: () => api.get<HistorySettings>(historySettingsPath), enabled: mihomo, retry: false }).data
    const ports = usePortsThroughVPN(mihomo)
    const [busy, setBusy] = useState('')
    const [problem, setProblem] = useState('')

    const items: Item[] = []
    if (mihomo && policy.data) {
        if (!policy.data.enabled) items.push({ id: 'kill-switch', group: 'Защита', title: 'Общий kill switch', now: 'Выключен', advice: 'Включён: при отказе VPN трафик ждёт, а не выходит напрямую.',
            restore: () => policy.saveAsync({ enabled: true }) })
        for (const service of routes?.services ?? []) {
            const state = serviceKillSwitch(policy.data, service.id)
            if (state.mode !== 'on' && service.target !== 'direct') items.push({ id: 'kill-switch-' + service.id, group: 'Защита', title: 'Kill switch · ' + service.name,
                now: state.mode === 'off' ? 'Всегда выключен' : 'Как в настройках', advice: 'Всегда включён.', restore: () => policy.saveAsync({ service_id: service.id, mode: 'on' }) })
        }
    }
    if (mihomo && ports.length > 0) items.push({ id: 'port-proxying', group: 'Защита', title: 'Порты через VPN',
        now: 'Только ' + ports.join(', '), advice: 'Все порты. Список меняется в «Исключения → Полный обход VPN» и действует после перезапуска XKeen.',
        link: '/exclusions' })
    if (mihomo && mode && mode.mode !== 'protected') items.push({ id: 'routing-mode', group: 'Защита', title: 'Неопознанный трафик',
        now: mode.mode === 'blocklist' ? 'Только по списку блокировок' : 'По правилам профиля', advice: 'Защищённый режим: всё неопознанное идёт через VPN.',
        restore: () => api.put('/api/routing/blocklist', { enabled: false }) })
    if (mihomo && routes) {
        for (const service of routes.services) {
            if (service.target === 'direct' && service.id !== 'steam') items.push({ id: 'route-' + service.id, group: 'Защита', title: 'Маршрут · ' + service.name, now: 'Напрямую',
                advice: isAiService(service.id) ? 'Через VPN, тем же сервером, что и остальные AI-карточки.' : 'Автовыбор VPN.',
                ...(isAiService(service.id) || !routes.default_service_target ? { link: '/services' }
                    : { restore: () => api.put('/api/service-routes', { service_id: service.id, target_id: routes.default_service_target }) }) })
        }
        const servers = new Set(aiServiceIds.flatMap(id => routes.services.find(service => service.id === id)?.target ?? []).filter(target => target && target !== 'direct'))
        if (servers.size > 1) items.push({ id: 'ai-group', group: 'Защита', title: 'AI и аналитика', now: 'У четырёх карточек разные серверы', advice: 'Один сервер на все четыре карточки.', link: '/services' })
    }
    if (mihomo && dns && !dns.foreign && dns.mode !== 'router') items.push({ id: 'dns', group: 'Автоматика', title: 'DNS ядра', now: 'Зашифрованный DNS', advice: 'Как у роутера.',
        restore: () => api.put('/api/dns', { mode: 'router' }) })
    if (status && !status.watchdog_active) items.push({ id: 'watchdog', group: 'Автоматика', title: 'Менять упавший сервер', now: 'Выключено', advice: 'Включено: панель сама уходит с сервера, который перестал отвечать.',
        restore: () => api.post('/api/watchdog/toggle', { active: true }) })
    if (settings && settings.subscription_refresh_minutes !== REFRESH) items.push({ id: 'refresh', group: 'Автоматика', title: 'Обновлять подписки',
        now: settings.subscription_refresh_minutes ? `Каждые ${settings.subscription_refresh_minutes} мин` : 'Не обновлять', advice: 'Каждый час.',
        restore: () => api.put('/api/panel/settings', { ...settings, subscription_refresh_minutes: REFRESH }) })
    if (mihomo && journal && journal.recent_enabled === false) items.push({ id: 'recent', group: 'Журнал и списки', title: 'Недавние соединения', now: 'Не запоминаются',
        advice: 'Включено: журнал показывает соединения, которые уже закрылись.', restore: () => api.put(historySettingsPath, { recent_off: false }) })
    if (mihomo && refilter?.supported && !refilter.auto) items.push({ id: 'refilter', group: 'Журнал и списки', title: 'Список блокировок Re:filter', now: 'Не обновляется панелью',
        advice: 'Обновлять раз в сутки.', restore: () => api.put('/api/components/refilter', { auto: true }) })

    const run = async (chosen: Item[]) => {
        setProblem('')
        for (const item of chosen) {
            if (!item.restore) continue
            setBusy(item.id)
            try {
                await item.restore()
            } catch (error) {
                setProblem(`${item.title}: ${error instanceof Error ? error.message : 'не удалось вернуть'}`)
                break
            }
        }
        setBusy('')
        await client.invalidateQueries()
    }
    const loading = !status || mihomo && (!policy.data || !routes || !mode)
    const restorable = items.filter(item => item.restore)
    const groups: Item['group'][] = ['Защита', 'Автоматика', 'Журнал и списки']

    return <>
        <PageTitle title='Рекомендуемые настройки' subtitle='Что отличается от рекомендованного и как это вернуть' back={{ to: '/settings', label: 'Настройки' }} />
        {problem && <p role='alert' className='px-4 text-sm text-destructive'>{problem}</p>}
        <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
            <div className='flex min-w-0 flex-col gap-5'>
                {loading ? <Group><Row label='Сверяем настройки…' /></Group>
                    : items.length === 0 ? <Group>
                        <Row icon={<IconShieldCheckFilled aria-hidden className='size-7 shrink-0 text-success' />} label='Всё как рекомендовано'
                            hint='Настройки защиты, автоматики и журнала совпадают с рекомендованными.' />
                    </Group>
                        : groups.map(group => {
                            const list = items.filter(item => item.group === group)
                            return list.length === 0 ? null : <Group key={group} title={group}>
                                {list.map(item => <div key={item.id} className='flex flex-wrap items-center gap-x-3 gap-y-1 py-3'>
                                    <div className='min-w-0 flex-1 basis-56'>
                                        <p className='text-[17px]'>{item.title}</p>
                                        <p className='mt-0.5 text-[13px] text-warning'>Сейчас · {item.now}</p>
                                        <p className='mt-0.5 text-[13px] text-muted-foreground'>Рекомендуется · {item.advice}</p>
                                    </div>
                                    {item.restore
                                        ? <button type='button' disabled={!!busy} onClick={() => void run([item])}
                                            className='min-h-11 shrink-0 cursor-pointer rounded-xl bg-fill px-3 text-[15px] font-medium text-tint disabled:cursor-default disabled:opacity-50'>{busy === item.id ? 'Возвращаем…' : 'Вернуть'}</button>
                                        : <Link to={item.link ?? '/settings'} className='flex min-h-11 shrink-0 items-center px-3 text-[15px] text-tint'>Открыть</Link>}
                                </div>)}
                            </Group>
                        })}
            </div>
            <div className='flex min-w-0 flex-col gap-5'>
                {restorable.length > 1 && <Group footer='Возврат к рекомендованному только усиливает защиту, поэтому подтверждение не требуется. Часть соединений переподключится.'>
                    <Row label={busy ? 'Возвращаем…' : `Вернуть всё (${restorable.length})`} tone='tint' disabled={!!busy} onClick={() => void run(restorable)} />
                </Group>}
                <Group title='Что считается рекомендованным' footer='Маршруты карточек, выбранные серверы, исключения и свои сервисы — ваш выбор; здесь они не оцениваются, кроме прямого выхода.'>
                    <Row label='Защита' hint='Общий kill switch включён, у карточек — «Всегда включён», неопознанный трафик идёт через VPN, через VPN идут все порты, AI-карточки на одном сервере.' />
                    <Row label='Автоматика' hint='Подписки обновляются каждый час, упавший сервер заменяется, ядро спрашивает адреса у роутера.' />
                    <Row label='Журнал и списки' hint='Недавние соединения запоминаются, список блокировок обновляется раз в сутки.' />
                </Group>
            </div>
        </div>
    </>
}
