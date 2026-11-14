import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconChevronDown, IconShield } from '@tabler/icons-react'
import { ServiceLogo } from '@/components/serviceLogo'
import { PageTitle } from '@/components/ios'
import { ServiceKillSwitch, useKillSwitch } from '@/components/killSwitch'
import { ServiceRoutePicker } from '@/components/serviceRoutePicker'
import { useMultiPools, usePanelSettings } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
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
}

interface ServiceRoutes {
    active_connections_pending?: boolean
    active: boolean
    guard_ready: boolean
    controller_ready?: boolean
    scope?: string
    services: Service[]
    targets: ServiceTarget[]
}

function CurrentRoute({route}: {route: InheritedRoute}) {
    if (route.kind === 'conditional') {
        return <p className='mt-2 text-sm text-muted-foreground'>Совпадения с Re:filter идут через основной VPN. Остальные адреса идут напрямую. Действуют исключения VPN.</p>
    }
    let current = 'Ядро пока не сообщило маршрут'
    if (route.kind === 'server' && route.endpoint) current = route.endpoint
    if (route.kind === 'direct') current = 'Напрямую, без VPN'
    if (route.kind === 'reject') current = 'Соединения блокируются'
    if (route.strategy === 'load-balance' && route.kind === 'unknown') current = 'Сервер зависит от соединения'

    return <p className='mt-2 break-words text-sm'><span className='text-muted-foreground'>Сейчас · </span>{current}</p>
}

function InheritedRouteInfo({route}: {route: InheritedRoute}) {
    const groupPath = [route.group, ...route.via].filter(Boolean).join(' → ')
    const members = route.members?.filter(member => member !== 'REJECT' && member !== 'REJECT-DROP')
    return (
        <div className='space-y-1'>
            <h3 className='font-medium'>Как выбран маршрут</h3>
            <div className='space-y-1 text-muted-foreground'>
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

function ServiceDetails({ service, mihomo, firewall, protectionEnabled }: {
    service: Service; mihomo: boolean; firewall: ReturnType<typeof useClaudeApiFirewall>; protectionEnabled?: boolean
}) {
    const claude = service.id === 'claude'
    const { state, install } = firewall
    const error = install.error ?? state.error
    const proxy = mihomo && !!service.target && service.target !== 'direct'
    const inherited = !service.target && service.inherited_route?.kind !== 'conditional' && service.inherited_route
    const domains = service.domains ?? []
    if (!claude && !proxy && !inherited && !domains.length) return null
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
                Подробнее <IconChevronDown aria-hidden className='size-4 transition-transform group-open/details:rotate-180' />
            </summary>
            <div className='space-y-4 pb-2'>
                {claude && !needsAttention && <div>
                    <h3 className='font-medium'>Фильтр API на роутере</h3>
                    <p className='mt-1 text-muted-foreground'>{state.data?.ready
                        ? 'Активен. Блокирует прямой выход к трём сетям Anthropic API и Console даже при остановке VPN.'
                        : state.data ? 'Выключен.' : 'Проверяем…'}</p>
                </div>}
                {inherited && <InheritedRouteInfo route={inherited} />}
                {proxy && <ClientProxy service={service} />}
                {domains.length > 0 && <div>
                    <h3 className='font-medium'>Домены сервиса</h3>
                    <ul aria-label='Домены сервиса' className='mt-1 max-h-36 overflow-y-auto break-words text-muted-foreground'>
                        {domains.map(d => <li key={d}>{d.replace(/^domain:/, '').replace(/^ext:geosite_v2fly\.dat:/, 'GeoSite · ')}</li>)}
                    </ul>
                </div>}
            </div>
        </details>
    </>
}

function ClientProxy({service}: {service: Service}) {
    const access = useMutation({
        mutationFn: () => api.post<{address: string; username: string; password: string}>('/api/service-routes/' + service.id + '/client'),
    })
    return (
        <div>
            <h3 className='font-medium'>Прокси для приложения</h3>
            <p className='mt-1 text-muted-foreground'>Чтобы приложение использовало этот маршрут для всех своих запросов, укажите HTTP-прокси и отключите в приложении прямой выход при его отказе.</p>
            {access.data ? (
                <div className='mt-3 space-y-1 break-all rounded-xl bg-fill p-3'>
                    <p>HTTP-прокси · {access.data.address}</p>
                    <p>Логин · <code>{access.data.username}</code></p>
                    <p>Пароль · <code>{access.data.password}</code></p>
                    <button type='button' className='min-h-10 text-tint' onClick={() => access.reset()}>Скрыть данные</button>
                </div>
            ) : <button type='button' disabled={access.isPending} className='mt-1 min-h-11 text-tint' onClick={() => access.mutate()}>{access.isPending ? 'Проверяем вход…' : 'Получить доступ'}</button>}
            {access.error && <p role='alert' className='text-destructive'>{access.error.message}</p>}
        </div>
    )
}

export function ServiceRoutesPage() {
    const qc = useQueryClient()
    const avoidCountries = usePanelSettings().data?.avoid_countries
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
    const firewall = useClaudeApiFirewall(!!view?.services.some(service => service.id === 'claude'))
    const error = change.error ?? query.error ?? killSwitch.error
    const scopes = useMultiPools(view?.scope === 'mihomo').data?.scopes
    const targets = view?.targets
    const options = useMemo(() => serviceRouteOptions(targets ?? [], scopes, avoidCountries), [targets, scopes, avoidCountries])

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
                                    ? 'Kill switch блокирует прямой выход при отказе VPN в работающем Mihomo.'
                                    : view.guard_ready
                                    ? (view.active ? 'При потере назначенного VPN защищённый маршрут блокируется.' : 'Выберите VPN для Claude, чтобы включить маршруты сервисов.')
                                    : 'Для применения нужен работающий сетевой фильтр на роутере.'}
                            </p>
                            {view.scope === 'mihomo' && <Link to='/settings#kill-switch' className='mt-1 inline-block text-sm text-tint'>Общий kill switch в настройках</Link>}
                        </div>
                    </div>
                    <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-3'>
                        {view.services.map(service => {
                            const isClaude = service.id === 'claude'
                            const selected = view.targets.find(t => t.id === service.target)
                            const busy = change.isPending && change.variables?.service_id === service.id
                            const label = 'service-' + service.id
                            return (
                                <section key={service.id} className='min-w-0 rounded-card bg-card p-4' aria-labelledby={label}>
                                    <div className='mb-3 flex items-center gap-3'>
                                        <span className='grid size-10 shrink-0 place-items-center'>
                                            <ServiceLogo id={service.id} className='size-8' />
                                        </span>
                                        <h2 id={label} className='font-semibold'>{service.name}</h2>
                                    </div>
                                    <label className='block text-sm text-muted-foreground' htmlFor={'vpn-' + service.id}>Маршрут</label>
                                    <ServiceRoutePicker
                                        id={'vpn-' + service.id}
                                        serviceName={service.name}
                                        groups={options}
                                        value={(busy ? change.variables?.target_id : service.target) || ''}
                                        inheritedLabel={isClaude ? 'Выберите VPN' : (view.scope === 'mihomo' ? 'По правилам сервиса в Mihomo' : 'По правилам Xray')}
                                        allowInherited={!isClaude}
                                        allowDirect={!isClaude && view.scope === 'mihomo'}
                                        disabled={change.isPending || !(view.guard_ready || (view.scope === 'mihomo' && view.controller_ready))}
                                        onSelect={targetId => {
                                            setNotice('')
                                            change.mutate({ service_id: service.id, target_id: targetId })
                                        }}
                                    />
                                    {!busy && !!selected?.sources?.length && <p className='mt-1 whitespace-pre-wrap text-sm text-muted-foreground [overflow-wrap:anywhere]'>
                                        {selected.sources.length === 1 ? 'Провайдер' : 'Провайдеры'} · {selected.sources.join(', ')}
                                    </p>}
                                    {!service.target && service.inherited_route && <CurrentRoute route={service.inherited_route} />}
                                    {view.scope === 'mihomo' && <ServiceKillSwitch policy={killSwitch} id={service.id} name={service.name} />}
                                    {busy && <p role='status' className='mt-2 text-sm text-muted-foreground'>Применяем маршрут…</p>}
                                    {!busy && service.blocked && view.active && <p className='mt-2 text-sm text-warning'>Ядро блокирует соединения этого сервиса</p>}
                                    <ServiceDetails service={service} mihomo={view.scope === 'mihomo'} firewall={firewall}
                                        protectionEnabled={killSwitch.data?.services?.claude ? killSwitch.data.services.claude === 'on' : killSwitch.data?.enabled} />
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
