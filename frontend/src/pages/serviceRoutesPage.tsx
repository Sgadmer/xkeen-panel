import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconShield, IconWorld } from '@tabler/icons-react'
import { serviceIcons } from '@/lib/serviceIcons'
import { PageTitle } from '@/components/ios'
import { ServiceKillSwitch, useKillSwitch } from '@/components/killSwitch'
import { useMultiPools, usePanelSettings } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { countryLabel, scopeLabel, withCountryFlag } from '@/lib/format'

interface InheritedRoute {
    group: string
    via: string[]
    kind: 'server' | 'direct' | 'reject' | 'unknown' | 'conditional'
    endpoint?: string
    strategy?: 'url-test' | 'fallback' | 'load-balance'
    members?: string[]
}

interface Service {
    id: string
    name: string
    domains: string[]
    target: string
    blocked: boolean
    inherited_route?: InheritedRoute
}

interface ServiceRoutes {
    active_connections_pending?: boolean
    active: boolean
    guard_ready: boolean
    controller_ready?: boolean
    scope?: string
    services: Service[]
    targets: { id: string; name: string; kind: 'server' | 'profile' | 'pool'; country?: string; sources?: string[] }[]
}

function InheritedRouteInfo({route}: {route: InheritedRoute}) {
    if (route.kind === 'conditional') {
        return <p className='mt-2 text-sm text-muted-foreground'>Совпадения с Re:filter идут через основной VPN. Остальные адреса идут напрямую. Действуют исключения VPN.</p>
    }
    let current = 'Ядро пока не сообщило маршрут'
    if (route.kind === 'server' && route.endpoint) current = route.endpoint
    if (route.kind === 'direct') current = 'Напрямую, без VPN'
    if (route.kind === 'reject') current = 'Соединения блокируются'
    if (route.strategy === 'load-balance' && route.kind === 'unknown') current = 'Сервер зависит от соединения'

    const groupPath = [route.group, ...route.via].filter(Boolean).join(' → ')
    const members = route.members?.filter(member => member !== 'REJECT' && member !== 'REJECT-DROP')
    return (
        <div className='mt-2 text-sm'>
            <p className='break-words'><span className='text-muted-foreground'>Сейчас · </span>{current}</p>
            <details className='mt-1.5'>
                <summary className='cursor-pointer text-tint'>Как выбран маршрут</summary>
                <div className='mt-2 space-y-2 text-muted-foreground'>
                    {groupPath && <p className='break-words'>Группа Mihomo · {groupPath}</p>}
                    {route.strategy === 'url-test' && <p>Mihomo сравнивает задержку доступных серверов и сам выбирает узел. Выбор может меняться.</p>}
                    {route.strategy === 'fallback' && <p>Mihomo использует первый доступный сервер группы. Если он перестаёт отвечать, ядро переходит к следующему.</p>}
                    {route.strategy === 'load-balance' && <p>Mihomo распределяет соединения между серверами группы.</p>}
                    {!route.strategy && route.group && <p>Для этого сервиса действует выбор его группы в Mihomo. Здесь можно назначить отдельный сервер или профиль.</p>}
                    {!route.group && <p>Для этой карточки Mihomo пока не подтвердил отдельную группу. Можно назначить сервер или профиль в списке выше.</p>}
                    {!!members?.length && (
                        <div>
                            <p className='font-medium text-foreground'>Кандидаты группы · {members.length}</p>
                            <ul className='mt-1 max-h-44 overflow-y-auto' aria-label='Кандидаты группы'>
                                {members.map(member => <li key={member} className='break-words py-0.5'>{member === 'DIRECT' ? 'Напрямую, без VPN' : member}</li>)}
                            </ul>
                        </div>
                    )}
                </div>
            </details>
        </div>
    )
}

interface ClaudeFirewall {
    available: boolean
    installed: boolean
    ready: boolean
}

function ClaudeApiFirewall({ protectionEnabled }: { protectionEnabled?: boolean }) {
    const client = useQueryClient()
    const key = ['claude-api-firewall']
    const path = '/api/service-routes/claude-api-firewall'
    const state = useQuery({queryKey: key, queryFn: () => api.get<ClaudeFirewall>(path), refetchInterval: 30000})
    const install = useMutation({
        mutationFn: () => api.post<ClaudeFirewall>(path),
        onSuccess: result => client.setQueryData(key, result),
        onError: () => { void client.invalidateQueries({queryKey: key}) },
    })
    const error = install.error ?? state.error
    return (
        <div className='mt-3 rounded-xl bg-fill p-3 text-sm'>
            <p className='font-semibold'>Защита адресов Anthropic API</p>
            {state.data && <p className='mt-1 text-muted-foreground'>{state.data.ready
                ? 'Роутер блокирует прямые пакеты к трём опубликованным IPv4/IPv6-сетям API и Console.'
                : protectionEnabled === false ? 'Kill switch Claude выключен. Прямой выход к адресам API разрешён.'
                : 'Фильтр блокирует прямой выход к трём сетям API и Console при остановке перехвата. Другие адреса Claude требуют отдельной защиты.'}</p>}
            {state.data?.available && !state.data.ready && protectionEnabled !== false && <button type='button' disabled={install.isPending}
                className='mt-2 min-h-11 rounded-xl px-3 font-semibold text-tint disabled:opacity-60'
                onClick={() => install.mutate()}>{install.isPending ? 'Проверяем правила…' : (state.data.installed ? 'Восстановить фильтр API' : 'Включить фильтр API')}</button>}
            {state.data && !state.data.available && <p className='mt-1 text-muted-foreground'>Для включения фильтра нужна панель на роутере.</p>}
            {error && <p role='alert' className='mt-2 text-destructive'>{error.message}</p>}
        </div>
    )
}

function ClientProxy({service}: {service: Service}) {
    const access = useMutation({
        mutationFn: () => api.post<{address: string; username: string; password: string}>('/api/service-routes/' + service.id + '/client'),
    })
    return (
        <details className='mt-3 text-sm'>
            <summary className='cursor-pointer text-tint'>Отдельный прокси для {service.name}</summary>
            <p className='mt-2 text-muted-foreground'>Клиент с обязательным HTTP-прокси использует этот маршрут и для сторонних адресов. В клиенте нужно отключить прямое подключение при отказе прокси.</p>
            {access.data ? (
                <div className='mt-3 space-y-1 break-all rounded-xl bg-fill p-3'>
                    <p>HTTP-прокси · {access.data.address}</p>
                    <p>Логин · <code>{access.data.username}</code></p>
                    <p>Пароль · <code>{access.data.password}</code></p>
                    <button type='button' className='min-h-10 text-tint' onClick={() => access.reset()}>Скрыть данные</button>
                </div>
            ) : <button type='button' disabled={access.isPending} className='mt-1 min-h-11 text-tint' onClick={() => access.mutate()}>{access.isPending ? 'Проверяем вход…' : 'Получить доступ'}</button>}
            {access.error && <p role='alert' className='text-destructive'>{access.error.message}</p>}
        </details>
    )
}

export function ServiceRoutesPage() {
    const qc = useQueryClient()
    const avoidCountries = usePanelSettings().data?.avoid_countries ?? []
    const [notice, setNotice] = useState('')
    const key = ['service-routes']
    const query = useQuery({
        queryKey: key,
        queryFn: () => api.get<ServiceRoutes>('/api/service-routes'),
        refetchInterval: 30000,
    })
    const change = useMutation({
        mutationFn: (selection: { service_id: string; target_id: string }) =>
            api.put<ServiceRoutes>('/api/service-routes', selection),
        onMutate: async () => { await qc.cancelQueries({ queryKey: key }) },
        onSuccess: async (view, selection) => {
            await qc.cancelQueries({ queryKey: key })
            qc.setQueryData(key, view)
            const service = view.services.find(item => item.id === selection.service_id)
            setNotice(view.active_connections_pending
                ? 'Маршрут сохранён. Часть прежних соединений ещё требует проверки.'
                : 'Маршрут сохранён' + (service ? ' · ' + service.name : ''))
        },
        onError: () => { void qc.invalidateQueries({ queryKey: key }) },
    })
    const view = query.data
    const killSwitch = useKillSwitch(view?.scope === 'mihomo')
    const error = change.error ?? query.error ?? killSwitch.error
    const scopes = useMultiPools(view?.scope === 'mihomo').data?.scopes
    const scopeById = new Map(scopes?.map(scope => [scope.id, scope]))
    const category = (target: ServiceRoutes['targets'][number]) =>
        target.kind === 'pool' ? (scopeById.get(target.id)?.kind ?? (target.country ? 'country' : 'pool')) : target.kind
    const groups = [
        ['all', 'Автовыбор'], ['country', 'Пулы стран'], ['custom', 'Мультипулы'], ['pool', 'Пулы'],
        ['profile', 'Режимы провайдера'], ['server', 'Отдельные серверы'],
    ] as const
    const options = groups.map(([kind, title]) => ({
        kind, title, targets: (view?.targets ?? []).filter(target => category(target) === kind).map(target => {
            const scope = scopeById.get(target.id)
            const name = scope ? scopeLabel(scope) : kind === 'country' ? countryLabel(target.country) : withCountryFlag(target.name, target.country)
            const label = [name, scope && String(scope.member_count), target.sources?.join(', '),
                kind === 'server' && target.country && avoidCountries.includes(target.country) && 'только вручную'].filter(Boolean).join(' · ')
            return { id: target.id, label }
        }),
    })).filter(group => group.targets.length)
    for (const group of options) {
        // A provider can reuse the same name for different configurations. Two
        // user-defined subscriptions or pools can also have identical names.
        const counts = new Map<string, number>()
        for (const item of group.targets) counts.set(item.label, (counts.get(item.label) ?? 0) + 1)
        for (const item of group.targets) if (counts.get(item.label)! > 1) item.label += ' · ' + item.id.slice(0, 8)
    }

    return (
        <>
            <PageTitle title='Маршруты сервисов' subtitle='Выберите для сервиса сервер, режим провайдера, страну или свой мультипул.' />
            {query.isPending && <p role='status'>Загружаем маршруты…</p>}
            {error && <p role='alert' className='rounded-xl bg-card p-4 text-destructive'>{error.message}</p>}
            {view && (
                <>
                    <div className='flex items-start gap-3 rounded-card bg-card p-4'>
                        <IconShield aria-hidden className='mt-0.5 size-5 shrink-0 text-tint' />
                        <div>
                            <p className='font-semibold'>{view.scope === 'mihomo' && view.active ? 'Маршруты Mihomo' : (view.active && view.guard_ready ? 'Защита маршрутов включена' : 'Защита маршрутов не подтверждена')}</p>
                            <p className='mt-1 text-sm text-muted-foreground'>
                                {view.scope === 'mihomo'
                                    ? 'Kill switch блокирует прямой выход при отказе VPN в работающем Mihomo. При полной остановке ядра продолжают действовать отдельные фильтры роутера. Фильтр адресов Anthropic API показан в карточке Claude.'
                                    : view.guard_ready
                                    ? (view.active ? 'При потере назначенного VPN защищённый маршрут блокируется.' : 'Выберите VPN для Claude, чтобы включить маршруты сервисов.')
                                    : 'Для применения нужен работающий сетевой фильтр на роутере.'}
                            </p>
                            {view.scope === 'mihomo' && <Link to='/settings#kill-switch' className='mt-1 inline-block text-sm text-tint'>Общий kill switch в настройках</Link>}
                        </div>
                    </div>
                    <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-3'>
                        {view.services.map(service => {
                            const Glyph = serviceIcons[service.id] ?? IconWorld
                            const isClaude = service.id === 'claude'
                            const missing = !!service.target && (isClaude || service.target !== 'direct') && !view.targets.some(t => t.id === service.target)
                            const busy = change.isPending && change.variables?.service_id === service.id
                            const label = 'service-' + service.id
                            return (
                                <section key={service.id} className='min-w-0 rounded-card bg-card p-4' aria-labelledby={label}>
                                    <div className='mb-3 flex items-center gap-3'>
                                        <span className={'grid size-10 shrink-0 place-items-center rounded-xl bg-fill ' + (isClaude ? 'text-orange-400' : 'text-tint')}>
                                            <Glyph aria-hidden className='size-6' stroke={1.8} />
                                        </span>
                                        <h2 id={label} className='font-semibold'>{service.name}</h2>
                                    </div>
                                    <label className='block text-sm text-muted-foreground' htmlFor={'vpn-' + service.id}>Маршрут</label>
                                    <select
                                        className='mt-1 min-h-11 w-full rounded-xl border border-white/10 bg-fill px-2 text-[15px] disabled:opacity-60'
                                        id={'vpn-' + service.id}
                                        value={(busy ? change.variables?.target_id : service.target) || ''}
                                        disabled={change.isPending || !(view.guard_ready || (view.scope === 'mihomo' && view.controller_ready))}
                                        onChange={e => {
                                            setNotice('')
                                            change.mutate({ service_id: service.id, target_id: e.target.value })
                                        }}
                                    >
                                        <option value='' disabled={isClaude}>{isClaude ? 'Выберите VPN' : (view.scope === 'mihomo' ? 'По правилам сервиса в Mihomo' : 'По правилам Xray')}</option>
                                        {!isClaude && view.scope === 'mihomo' && <option value='direct'>Напрямую</option>}
                                        {missing && <option value={service.target} disabled>Назначенный маршрут недоступен</option>}
                                        {options.map(({kind, title, targets}) => (
                                            <optgroup key={kind} label={title}>
                                                {targets.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                                            </optgroup>
                                        ))}
                                    </select>
                                    {!service.target && service.inherited_route && <InheritedRouteInfo route={service.inherited_route} />}
                                    {view.scope === 'mihomo' && <ServiceKillSwitch policy={killSwitch} id={service.id} name={service.name} />}
                                    {busy && <p role='status' className='mt-2 text-sm text-muted-foreground'>Применяем маршрут…</p>}
                                    {isClaude && <ClaudeApiFirewall protectionEnabled={killSwitch.data?.services?.claude
                                        ? killSwitch.data.services.claude === 'on' : killSwitch.data?.enabled} />}
                                    {view.scope === 'mihomo' && !!service.target && service.target !== 'direct' && <ClientProxy service={service} />}
                                    {!busy && service.blocked && view.active && <p className='mt-2 text-sm text-warning'>Ядро блокирует соединения этого сервиса</p>}
                                    {service.domains?.length > 0 && (
                                        <details className='mt-3 text-sm text-muted-foreground'>
                                            <summary className='cursor-pointer'>Домены сервиса</summary>
                                            <p className='mt-2 break-words'>{service.domains.map(d => d.replace(/^domain:/, '').replace(/^ext:geosite_v2fly\.dat:/, 'GeoSite · ')).join(' · ')}</p>
                                        </details>
                                    )}
                                </section>
                            )
                        })}
                    </div>
                    <p role='status' className='text-sm text-muted-foreground'>{notice}</p>
                </>
            )}
        </>
    )
}
