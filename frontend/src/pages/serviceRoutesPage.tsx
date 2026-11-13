import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
    IconAsterisk, IconBrain, IconBrandAmazon, IconBrandDiscord, IconBrandDisney,
    IconBrandFacebook, IconBrandGithub, IconBrandGoogle, IconBrandHbo, IconBrandInstagram,
    IconBrandLine, IconBrandNetflix, IconBrandOpenai, IconBrandSpotify, IconBrandSteam,
    IconBrandTelegram, IconBrandTwitch, IconBrandTwitter, IconBrandWhatsapp,
    IconBrandXbox, IconBrandYoutube, IconDeviceGamepad2, IconLetterH, IconPlayerPlay,
    IconShield, IconWorld, type Icon,
} from '@tabler/icons-react'
import { PageTitle } from '@/components/ios'
import { api } from '@/lib/api'

interface Service {
    id: string
    name: string
    domains: string[]
    target: string
    blocked: boolean
    route_name?: string
}

interface ServiceRoutes {
    active_connections_pending?: boolean
    active: boolean
    guard_ready: boolean
    controller_ready?: boolean
    scope?: string
    services: Service[]
    targets: { id: string; name: string; kind: 'server' | 'profile' }[]
}

const icons: Record<string, Icon> = {
    claude: IconAsterisk, ai: IconBrain, openai: IconBrandOpenai,
    youtube: IconBrandYoutube, telegram: IconBrandTelegram, discord: IconBrandDiscord,
    spotify: IconBrandSpotify, github: IconBrandGithub, steam: IconBrandSteam,
    playstation: IconDeviceGamepad2, xbox: IconBrandXbox, instagram: IconBrandInstagram,
    whatsapp: IconBrandWhatsapp, facebook: IconBrandFacebook, netflix: IconBrandNetflix,
    twitch: IconBrandTwitch, disney: IconBrandDisney, primevideo: IconPlayerPlay,
    amazon: IconBrandAmazon, twitter: IconBrandTwitter, hulu: IconLetterH,
    hbo: IconBrandHbo, line: IconBrandLine, google: IconBrandGoogle,
}

interface ClaudeFirewall {
    available: boolean
    installed: boolean
    ready: boolean
}

function ClaudeApiFirewall() {
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
                : 'Фильтр блокирует прямой выход к трём сетям API и Console при остановке перехвата. Другие адреса Claude требуют отдельной защиты.'}</p>}
            {state.data?.available && !state.data.ready && <button type='button' disabled={install.isPending}
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
        onSuccess: (view, selection) => {
            qc.setQueryData(key, view)
            const service = view.services.find(item => item.id === selection.service_id)
            setNotice(view.active_connections_pending
                ? 'Маршрут сохранён. Часть прежних соединений ещё требует проверки.'
                : 'Маршрут сохранён' + (service ? ' · ' + service.name : ''))
        },
        onError: () => { void qc.invalidateQueries({ queryKey: key }) },
    })
    const view = query.data
    const error = change.error ?? query.error

    return (
        <>
            <PageTitle title='Маршруты сервисов' back={{ to: '/settings', label: 'Настройки' }} subtitle='Выберите для сервиса отдельный сервер или сборный профиль из подписки.' />
            {query.isPending && <p role='status'>Загружаем маршруты…</p>}
            {error && <p role='alert' className='rounded-xl bg-card p-4 text-destructive'>{error.message}</p>}
            {view && (
                <>
                    <div className='flex items-start gap-3 rounded-card bg-card p-4'>
                        <IconShield aria-hidden className='mt-0.5 size-5 shrink-0 text-tint' />
                        <div>
                            <p className='font-semibold'>{view.active && view.guard_ready ? 'Защита маршрутов включена' : (view.scope === 'mihomo' && view.active ? 'Назначенные маршруты работают' : 'Защита маршрутов не подтверждена')}</p>
                            <p className='mt-1 text-sm text-muted-foreground'>
                                {view.guard_ready
                                    ? (view.active ? 'При потере назначенного VPN защищённый маршрут блокируется.' : 'Выберите VPN для Claude, чтобы включить маршруты сервисов.')
                                    : (view.scope === 'mihomo'
                                        ? 'При полной остановке перехвата подтверждена только защита адресов, для которых включён сетевой фильтр. Состояние фильтра Anthropic показано в карточке Claude.'
                                        : 'Для применения нужен работающий сетевой фильтр на роутере.')}
                            </p>
                        </div>
                    </div>
                    <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-3'>
                        {view.services.map(service => {
                            const Glyph = icons[service.id] ?? IconWorld
                            const isClaude = service.id === 'claude'
                            const missing = !!service.target && service.target !== 'direct' && !view.targets.some(t => t.id === service.target)
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
                                        value={service.target || ''}
                                        disabled={change.isPending || !(view.guard_ready || (view.scope === 'mihomo' && view.controller_ready))}
                                        onChange={e => {
                                            setNotice('')
                                            change.mutate({ service_id: service.id, target_id: e.target.value })
                                        }}
                                    >
                                        <option value='' disabled={isClaude && !!service.target}>{service.route_name && !service.target ? 'Основной маршрут · ' + service.route_name : (isClaude ? 'VPN не выбран' : 'По основным правилам')}</option>
                                        {!isClaude && view.scope === 'mihomo' && <option value='direct'>Напрямую</option>}
                                        {missing && <option value={service.target} disabled>Цель отсутствует в подписке</option>}
                                        {(['server', 'profile'] as const).map(kind => (
                                            <optgroup key={kind} label={kind === 'profile' ? 'Сборные профили' : 'Серверы'}>
                                                {view.targets.filter(t => t.kind === kind).map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                                            </optgroup>
                                        ))}
                                    </select>
                                    {busy && <p role='status' className='mt-2 text-sm text-muted-foreground'>Применяем маршрут…</p>}
                                    {isClaude && <ClaudeApiFirewall />}
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
