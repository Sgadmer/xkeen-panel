import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconChevronDown, IconSearch, IconShield } from '@tabler/icons-react'
import { AiRouteWarning } from '@/components/aiRouteWarning'
import { aiServiceIds, isAiService } from '@/lib/aiServiceGroup'
import { ServiceLogo } from '@/components/serviceLogo'
import { ServiceOrderControl, useServiceOrder } from '@/components/serviceOrder'
import { PageTitle } from '@/components/ios'
import { ServiceKillSwitch, serviceKillSwitch, useKillSwitch } from '@/components/killSwitch'
import { ServiceRoutePicker } from '@/components/serviceRoutePicker'
import { useMultiPools, usePanelSettings } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { countryLabel, withCountryFlag } from '@/lib/format'
import { serviceRouteOptions, type ServiceTarget } from '@/lib/serviceRouteOptions'

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
    current_route?: {
        pool?: string
        pool_country?: string
        kind: 'server' | 'direct' | 'reject' | 'unknown'
        name?: string
        country?: string
        source?: string
    }
}

interface ServiceRoutes {
    active_connections_pending?: boolean
    active: boolean
    guard_ready: boolean
    controller_ready?: boolean
    scope?: string
    default_service_target?: string
    service_auto_default?: boolean
    services: Service[]
    targets: ServiceTarget[]
}

function currentRoute(route: InheritedRoute) {
    if (route.kind === 'conditional') {
        return 'По списку блокировок'
    }
    let current = 'Ядро пока не сообщило маршрут'
    if (route.kind === 'server' && route.endpoint) current = route.endpoint
    if (route.kind === 'direct') current = 'Напрямую, без VPN'
    if (route.kind === 'reject') current = 'Соединения блокируются'
    if (route.strategy === 'load-balance' && route.kind === 'unknown') current = 'Сервер зависит от соединения'

    return current
}

function routeSummary(service: Service) {
    const current = service.current_route
    if (service.target === 'direct') return 'Через домашнего провайдера'
    if (current?.kind === 'reject' || service.blocked) return 'Соединение заблокировано'
    if (current?.kind === 'direct') return 'Напрямую'
    if (current?.kind === 'server') {
        const location = countryLabel(current.country) || 'Локация неизвестна'
        return current.source ? current.source + ' → ' + location : location
    }
    if (!service.target && service.inherited_route) {
        if (current?.kind === 'unknown') return 'Локация неизвестна'
        if (service.inherited_route.kind === 'server') return 'Локация неизвестна'
        return currentRoute(service.inherited_route)
    }
    return 'Локация неизвестна'
}

function InheritedRouteInfo({route, fresh}: {route: InheritedRoute; fresh: boolean}) {
    if (route.kind === 'conditional') {
        return <div>
            <h3 className='font-medium'>Когда используется VPN</h3>
            <p className='mt-1 text-muted-foreground'>Роутер сверяет адрес со списком блокировок Re:filter. Если адрес есть в списке, запрос идёт через основной VPN. Остальные адреса открываются напрямую. Ваши исключения тоже действуют.</p>
        </div>
    }
    const groupPath = [route.group, ...route.via].filter(Boolean).join(' → ')
    const members = route.members?.filter(member => member !== 'REJECT' && member !== 'REJECT-DROP')
    return (
        <div className='space-y-1'>
            <h3 className='font-medium'>Как выбран маршрут</h3>
            <div className='space-y-1 text-muted-foreground'>
                {fresh && <p className='break-words'>Сейчас · {currentRoute(route)}</p>}
                {groupPath && <p className='break-words'>Маршрут в Mihomo · {groupPath}</p>}
                {route.strategy === 'url-test' && <p>Mihomo сравнивает задержку доступных серверов и сам выбирает узел. Выбор может меняться.</p>}
                {route.strategy === 'fallback' && <p>Mihomo использует первый доступный сервер группы. Если он перестаёт отвечать, ядро переходит к следующему.</p>}
                {route.strategy === 'load-balance' && <p>Mihomo распределяет соединения между серверами группы.</p>}
                {!route.strategy && route.group && <p>Роутер использует маршрут из настроек Mihomo. Чтобы выбрать другой, нажмите «Маршрут» в этой карточке.</p>}
                {!route.group && <p>Роутер пока не сообщил, каким путём идёт этот сервис.</p>}
                {!!members?.length && (
                    <div>
                        <p className='font-medium text-foreground'>Кандидаты группы · {members.length}</p>
                        <ul className='mt-1 max-h-44 overflow-y-auto' aria-label='Кандидаты группы'>
                            {members.map(member => <li key={member} className='break-words py-0.5'>{member === 'DIRECT' ? 'Напрямую, без VPN' : member}</li>)}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    )
}

interface ClaudeFirewall {
    available: boolean
    installed: boolean
    ready: boolean
}

function useClaudeApiFirewall(enabled: boolean) {
    const client = useQueryClient()
    const key = ['claude-api-firewall']
    const path = '/api/service-routes/claude-api-firewall'
    const state = useQuery({queryKey: key, queryFn: () => api.get<ClaudeFirewall>(path), enabled, refetchInterval: enabled ? 30000 : false})
    const install = useMutation({
        mutationFn: () => api.post<ClaudeFirewall>(path),
        onSuccess: result => client.setQueryData(key, result),
        onError: () => { void client.invalidateQueries({queryKey: key}) },
    })
    return { state, install }
}

function ServiceDetails({ service, selected, fresh, mihomo, firewall, protectionEnabled }: {
    service: Service; selected?: ServiceTarget; fresh: boolean; mihomo: boolean; firewall: ReturnType<typeof useClaudeApiFirewall>; protectionEnabled?: boolean
}) {
    const claude = service.id === 'claude'
    const analytics = service.id === 'analytics'
    const { state, install } = firewall
    const error = install.error ?? state.error
    const proxy = mihomo && !!service.target && service.target !== 'direct'
    const inherited = service.target ? undefined : service.inherited_route
    const providers = selected?.sources?.join(', ')
    const live = fresh && service.target !== 'direct' ? service.current_route : undefined
    const domains = service.domains ?? []
    if (!claude && !analytics && !proxy && !inherited && !domains.length) return null
    const needsAttention = claude && (!!error || (!!state.data && !state.data.ready && protectionEnabled !== false))
    return <>
        {needsAttention && <div className='mt-2 text-sm' role='status'>
            <p className='text-warning'>Фильтр API на роутере · {error ? 'ошибка проверки' : state.data?.available ? 'не активен' : 'недоступен'}</p>
            {state.data?.available && !state.data.ready && protectionEnabled !== false && <button type='button' disabled={install.isPending}
                className='mt-2 min-h-11 rounded-xl px-3 font-semibold text-tint disabled:opacity-60'
                onClick={() => install.mutate()}>{install.isPending ? 'Проверяем правила…' : (state.data.installed ? 'Восстановить фильтр API' : 'Включить фильтр API')}</button>}
            {state.data && !state.data.available && <p className='mt-1 text-muted-foreground'>Для включения фильтра нужна панель на роутере.</p>}
            {error && <p role='alert' className='mt-2 text-destructive'>{error.message}</p>}
        </div>}
        <details className='group/details mt-2 border-t border-separator text-sm'>
            <summary className='flex min-h-10 cursor-pointer list-none items-center justify-between gap-2 text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden'>
                <span>Подробнее</span>
                <IconChevronDown aria-hidden className='size-4 shrink-0 transition-transform group-open/details:rotate-180' />
            </summary>
            <div className='space-y-4 pb-2'>
                {analytics && <div>
                    <h3 className='font-medium'>Общие служебные запросы</h3>
                    <p className='mt-1 text-muted-foreground'>Приложения отправляют сюда отчёты об ошибках, данные о работе и сигналы для проверки безопасности аккаунта. Эти адреса общие для разных приложений: выбранный маршрут действует для всех их запросов к адресам из этой карточки.</p>
                    <p className='mt-1 text-muted-foreground'>Список известных адресов обновляется автоматически раз в сутки.</p>
                </div>}
                {live?.kind === 'server' && live.name && <p className='break-words'>{inherited?.kind === 'conditional' ? 'Для адресов из списка блокировок' : 'Сейчас'} · {[countryLabel(live.pool_country) || live.pool, withCountryFlag(live.name, live.country)].filter(Boolean).join(' → ')}</p>}
                {(live?.source || providers) && <p className='break-words'>Провайдер{!live?.source && (selected?.sources?.length ?? 0) > 1 ? 'ы' : ''} · {live?.source || providers}</p>}
                {claude && !needsAttention && <div>
                    <h3 className='font-medium'>Фильтр API на роутере</h3>
                    <p className='mt-1 text-muted-foreground'>{state.data?.ready
                        ? 'Активен. Блокирует прямой выход к трём сетям Anthropic API и Console даже при остановке VPN.'
                        : state.data ? 'Выключен.' : 'Проверяем…'}</p>
                </div>}
                {inherited && <InheritedRouteInfo route={inherited} fresh={fresh} />}
                {proxy && <ClientProxy service={service} />}
                {domains.length > 0 && <div>
                    <h3 className='font-medium'>Домены сервиса</h3>
                    <ul aria-label='Домены сервиса' className='mt-1 max-h-36 overflow-y-auto break-words text-muted-foreground'>
                        {domains.map(d => <li key={d}>{d.replace(/^(domain|full):/, '').replace(/^ext:geosite_v2fly\.dat:/, 'GeoSite · ')}</li>)}
                    </ul>
                </div>}
            </div>
        </details>
    </>
}

function ClientProxy({service}: {service: Service}) {
    const [showPassword, setShowPassword] = useState(false)
    const access = useMutation({
        mutationFn: () => api.post<{address: string; username: string; password: string}>('/api/service-routes/' + service.id + '/client'),
    })
    return (
        <div>
            <h3 className='font-medium'>Прокси для приложения</h3>
            <p className='mt-1 text-muted-foreground'>Через домашний Wi-Fi или кабель ничего вводить не нужно. Роутер сам направляет знакомые ему адреса сервиса по выбранному маршруту.</p>
            <p className='mt-2 text-muted-foreground'>Прокси пригодится, если приложение обращается ещё и к другим сайтам, например за файлами. Введите адрес, логин и пароль в разделе «HTTP-прокси» самого приложения. Тогда всё, что оно отправит через прокси, пойдёт по маршруту «{service.name}». Если в приложении есть запасной прямой выход, отключите его.</p>
            {access.data ? (
                <div className='mt-3 space-y-1 break-all rounded-xl bg-fill p-3'>
                    <p>HTTP-прокси · {access.data.address}</p>
                    <p>Логин прокси · <code>{access.data.username}</code></p>
                    <p>Пароль прокси · <code>{showPassword ? access.data.password : '••••••••'}</code></p>
                    <div className='flex flex-wrap gap-x-4'>
                        <button type='button' className='min-h-10 text-tint' onClick={() => setShowPassword(!showPassword)}>
                            {showPassword ? 'Скрыть пароль' : 'Показать пароль'}
                        </button>
                        <button type='button' className='min-h-10 text-muted-foreground' onClick={() => { setShowPassword(false); access.reset() }}>Скрыть данные</button>
                    </div>
                </div>
            ) : <button type='button' disabled={access.isPending} className='mt-1 min-h-11 text-tint' onClick={() => access.mutate()}>{access.isPending ? 'Проверяем прокси…' : 'Настроить прокси вручную'}</button>}
            {access.error && <p role='alert' className='text-destructive'>{access.error.message}</p>}
        </div>
    )
}

export function ServiceRoutesPage() {
    const qc = useQueryClient()
    const avoidCountries = usePanelSettings().data?.avoid_countries
    const [notice, setNotice] = useState('')
    const [search, setSearch] = useState('')
    const [warning, setWarning] = useState<{serviceId: string; serviceName: string; targetId: string; targetLabel: string; targetKind?: ServiceTarget['kind']} | null>(null)
    const key = ['service-routes']
    const query = useQuery({
        queryKey: key,
        queryFn: () => api.get<ServiceRoutes>('/api/service-routes'),
        refetchInterval: query => query.state.data?.scope === 'mihomo' ? 5000 : 30000,
        refetchOnWindowFocus: 'always',
    })
    const change = useMutation({
        mutationFn: (selection: { service_id: string; target_id: string; ai_group?: boolean } | 'auto-default') =>
            selection === 'auto-default' ? api.post<ServiceRoutes>('/api/service-routes/auto-default')
                : selection.ai_group ? api.put<ServiceRoutes>('/api/service-routes/ai-group', { target_id: selection.target_id })
                    : api.put<ServiceRoutes>('/api/service-routes', selection),
        onMutate: async () => { await qc.cancelQueries({ queryKey: key }) },
        onSuccess: async (view, selection) => {
            await qc.cancelQueries({ queryKey: key })
            qc.setQueryData(key, view)
            const service = selection !== 'auto-default' && view.services.find(item => item.id === selection.service_id)
            setWarning(null)
            const saved = selection !== 'auto-default' && selection.ai_group ? 'Один маршрут сохранён для AI и аналитики' : selection === 'auto-default' ? 'Автовыбор включён' : 'Маршрут сохранён' + (service ? ' · ' + service.name : '')
            setNotice(view.active_connections_pending ? saved + '. Проверяем прежние соединения.' : saved)
        },
        onError: () => { void qc.invalidateQueries({ queryKey: key }) },
    })
    const view = query.data
    const order = useServiceOrder(view?.services ?? [])
    const others = order.services.filter(service => !isAiService(service.id))
    const wanted = search.trim().toLowerCase()
    const found = wanted ? others.filter(service => service.name.toLowerCase().includes(wanted) || service.id.includes(wanted)) : others
    const mihomo = view?.scope === 'mihomo'
    const needsMigration = mihomo && view.service_auto_default === false
    const unassigned = needsMigration ? view.services.filter(service => !service.target) : []
    const autoCount = unassigned.filter(service => service.id !== 'steam').length
    const pendingService = change.isPending && change.variables !== 'auto-default' ? change.variables : undefined
    const killSwitch = useKillSwitch(view?.scope === 'mihomo')
    const claudeProtection = killSwitch.data && serviceKillSwitch(killSwitch.data, 'claude').enabled
    const firewall = useClaudeApiFirewall(!!view?.services.some(service => service.id === 'claude'))
    const error = change.error ?? query.error ?? killSwitch.error
    const scopes = useMultiPools(view?.scope === 'mihomo').data?.scopes
    const targets = view?.targets
    const defaultServiceTarget = mihomo ? view.default_service_target : undefined
    const options = useMemo(() => serviceRouteOptions(targets ?? [], scopes, avoidCountries, defaultServiceTarget), [targets, scopes, avoidCountries, defaultServiceTarget])

    const renderService = (service: Service) => {
        if (!view) return null
        const isClaude = service.id === 'claude'
        const selected = view.targets.find(t => t.id === service.target)
        // A selected server that left every subscription cannot be shown in the picker.
        const lost = !!service.target && service.target !== 'direct' && !selected
        const summary = query.isError ? 'Не удалось обновить маршрут' : lost ? 'Сервер пропал из подписок · выберите маршрут заново' : routeSummary(service)
        const busy = pendingService?.service_id === service.id || !!pendingService?.ai_group && isAiService(service.id)
        const label = 'service-' + service.id
        return (
            <section key={service.id} className='min-w-0 rounded-card bg-card p-4' aria-labelledby={label}>
                <div className='mb-3 flex items-center gap-3'>
                    <span className='grid size-10 shrink-0 place-items-center'>
                        <ServiceLogo id={service.id} className='size-8' />
                    </span>
                    <h2 id={label} className='min-w-0 flex-1 font-semibold'>{service.name}</h2>
                    {mihomo && <Link to={'/journal?service=' + encodeURIComponent(service.id)} aria-label={'Журнал сервиса ' + service.name}
                        className='shrink-0 py-1 text-sm text-tint hover:underline'>Журнал</Link>}
                </div>
                <label className='block text-sm text-muted-foreground' htmlFor={'vpn-' + service.id}>Маршрут</label>
                <ServiceRoutePicker
                    id={'vpn-' + service.id}
                    serviceName={service.name}
                    groups={options}
                    value={(busy && pendingService ? pendingService.target_id : service.target) || ''}
                    inheritedLabel={isClaude || (mihomo && !needsMigration) ? 'Выберите VPN' : 'По правилам роутера'}
                    allowInherited={!isClaude && !mihomo}
                    allowDirect={!isClaude && view.scope === 'mihomo'}
                    disabled={change.isPending || !(view.guard_ready || (view.scope === 'mihomo' && view.controller_ready))}
                    onSelect={targetId => {
                        if (targetId === service.target) return
                        setNotice('')
                        change.reset()
                        if (isAiService(service.id)) {
                            const target = view?.targets.find(item => item.id === targetId)
                            setWarning({serviceId: service.id, serviceName: service.name, targetId, targetLabel: target?.name || (targetId === 'direct' ? 'Напрямую' : 'Выбранный VPN'), targetKind: target?.kind})
                        } else change.mutate({ service_id: service.id, target_id: targetId })
                    }}
                />
                <p className='mt-1 min-h-5 truncate text-sm leading-5 text-muted-foreground' title={summary || undefined}>
                    {busy ? 'Меняем маршрут…' : summary}
                </p>
                {view.scope === 'mihomo' && <ServiceKillSwitch policy={killSwitch} id={service.id} name={service.name} direct={service.target === 'direct'} />}
                <ServiceDetails service={service} selected={selected} fresh={!query.isError} mihomo={view.scope === 'mihomo'} firewall={firewall}
                    protectionEnabled={claudeProtection} />
            </section>
        )
    }

    return (
        <>
            <div className='flex flex-wrap items-center justify-between gap-x-4 gap-y-1'>
                <PageTitle title='Сервисы' subtitle='Выберите в карточке, как сервис выходит в интернет.' />
                {order.services.length > 1 && <ServiceOrderControl services={order.services.filter(service => !isAiService(service.id))} save={order.save} />}
            </div>
            {query.isPending && <p role='status'>Загружаем маршруты…</p>}
            {error && <p role='alert' className='rounded-xl bg-card p-4 text-destructive'>{error.message}</p>}
            {warning && <AiRouteWarning key={warning.serviceId + ':' + warning.targetId}
                serviceName={warning.serviceName} targetLabel={warning.targetLabel} targetKind={warning.targetKind}
                canApplyGroup={!!mihomo && warning.targetId !== 'direct' && !!warning.targetId && aiServiceIds.every(id => view?.services.some(service => service.id === id))}
                busy={change.isPending} error={change.error?.message}
                onCancel={() => { if (!change.isPending) { setWarning(null); change.reset() } }}
                onSingle={() => { if (!change.isPending) change.mutate({ service_id: warning.serviceId, target_id: warning.targetId }) }}
                onGroup={() => { if (!change.isPending) change.mutate({ service_id: 'ai-group', target_id: warning.targetId, ai_group: true }) }} />}
            {view && (
                <>
                    {mihomo ? <p className='px-1 text-sm text-muted-foreground'>
                        Kill switch в карточке: если её VPN-сервер не отвечает, сервис ждёт связи и не выходит напрямую.{' '}
                        <Link to='/settings/protection' className='text-tint'>Общая защита</Link>{' · '}
                        <Link to='/settings/components#service-lists' className='text-tint'>Списки адресов сервисов</Link>
                    </p> : <div className='flex items-start gap-3 rounded-card bg-card p-4'>
                        <IconShield aria-hidden className='mt-0.5 size-5 shrink-0 text-tint' />
                        <div>
                            <p className='font-semibold'>{view.active && view.guard_ready ? 'Защита маршрутов включена' : 'Защита маршрутов не подтверждена'}</p>
                            <p className='mt-1 text-sm text-muted-foreground'>
                                {view.guard_ready
                                    ? (view.active ? 'При потере назначенного VPN защищённый маршрут блокируется.' : 'Выберите VPN для Claude, чтобы включить маршруты сервисов.')
                                    : 'Для применения нужен работающий сетевой фильтр на роутере.'}
                            </p>
                        </div>
                    </div>}
                    {needsMigration && <div className='rounded-card bg-card p-4'>
                        <h2 className='font-semibold'>Автовыбор для сервисов</h2>
                        <p className='mt-1 text-sm text-muted-foreground'>
                            {autoCount ? <>Карточек для перевода на VPN — {autoCount}. Для них роутер сам выберет сервер из пула «Все локации». </> : 'Новые сервисы будут использовать автовыбор VPN. '}
                            {unassigned.some(service => service.id === 'steam') && 'Steam будет открываться напрямую. '}
                            Ваши ручные назначения сохранятся.
                        </p>
                        <button type='button' disabled={change.isPending || !view.controller_ready || !defaultServiceTarget}
                            className='mt-3 min-h-11 rounded-xl bg-primary px-4 font-semibold text-primary-foreground disabled:opacity-50'
                            onClick={() => { setNotice(''); change.mutate('auto-default') }}>
                            {change.isPending && change.variables === 'auto-default' ? 'Применяем…' : 'Применить'}
                        </button>
                    </div>}
                    <section aria-labelledby='ai-group-title' className='rounded-[28px] border border-tint/30 bg-tint/5 p-3 sm:p-4'>
                        <header className='mb-4 px-1'>
                            <h2 id='ai-group-title' className='flex items-center gap-2 text-lg font-semibold'><IconShield aria-hidden className='size-5 text-tint' /> AI и аналитика</h2>
                            <p className='mt-2 max-w-5xl text-sm leading-relaxed text-foreground/90'>Выберите один и тот же сервер для всех четырёх карточек: так у AI-сервисов и их служебных запросов будет один выход.</p>
                            <details className='group/ai mt-1 max-w-5xl text-sm'>
                                <summary className='flex min-h-9 cursor-pointer list-none items-center gap-1 text-tint [&::-webkit-details-marker]:hidden'>
                                    Почему это важно и что с голосовым чатом
                                    <IconChevronDown aria-hidden className='size-4 shrink-0 transition-transform group-open/ai:rotate-180' />
                                </summary>
                                <div className='space-y-2 pb-1 leading-relaxed text-muted-foreground'>
                                    <p>AI-приложения и агенты отправляют служебные запросы, которые идут по правилам аналитики, а не самого AI-сервиса. Один сервер сохраняет одинаковый выход и снижает риск проблем с аккаунтом, особенно у Claude / Anthropic.</p>
                                    <p>Для постоянного общего выхода выбирайте конкретный сервер: один пул может использовать разные узлы.</p>
                                    <p><strong className='font-semibold text-warning'>Голосовой чат.</strong> Для голоса Claude и ChatGPT подходят не все VPN-локации, даже если переписка работает. Иногда нужно попробовать несколько серверов.</p>
                                </div>
                            </details>
                        </header>
                        <div className='grid gap-3 sm:grid-cols-2 2xl:grid-cols-4'>
                            {aiServiceIds.flatMap(id => { const service = view.services.find(item => item.id === id); return service ? [renderService(service)] : [] })}
                        </div>
                    </section>
                    {others.length > 6 && <label className='flex min-h-11 items-center gap-2 rounded-xl bg-fill px-3 sm:max-w-sm'>
                        <IconSearch aria-hidden className='size-4 shrink-0 text-muted-foreground' stroke={2.2} />
                        <span className='sr-only'>Найти сервис</span>
                        <input type='search' value={search} onChange={event => setSearch(event.target.value)} placeholder='Найти сервис'
                            className='min-w-0 flex-1 bg-transparent text-[16px] outline-none placeholder:text-muted-foreground' />
                    </label>}
                    <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-3'>
                        {found.map(renderService)}
                    </div>
                    {others.length > 0 && found.length === 0 && <p className='px-1 text-sm text-muted-foreground'>Такого сервиса нет в списке.</p>}
                    <p role='status' className='text-sm text-muted-foreground'>{notice}</p>
                </>
            )}
        </>
    )
}
