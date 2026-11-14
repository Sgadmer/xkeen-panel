import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Group, Row } from '@/components/ios'
import { useDevices, usePanelSettings } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { RouterMetrics, type RouterSample } from '@/components/routerMetrics'
import { ServiceLogo } from '@/components/serviceLogo'
import { serverPathDetail, type ServerCountries } from '@/lib/serverPath'

type ServerLocation = ServerCountries & { name?: string; country?: string; source?: string }
type Flow = {
    id: string; device: string; host: string; port?: string; network?: string; rule?: string
    service_id?: string; route: string[]; start: string
    exit?: ServerLocation & { kind: 'server' | 'direct' | 'reject' | 'unresolved' }
    pool_current?: ServerLocation
}
type Activity = {
    system: RouterSample
    history?: RouterSample[]
    connections: Flow[]
    services?: { id: string; name: string }[]
    connections_error?: string
}

const clock = new Intl.DateTimeFormat('ru', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

function FlowRoute({ flow, service, full }: { flow: Flow; service?: string; full: boolean }) {
    const location = flow.exit?.kind === 'server' ? flow.exit : flow.pool_current
    const path = serverPathDetail(location, full)
    const node = path || location?.name
    const hops = [...flow.route]
    if (node && flow.exit?.kind === 'server' && (hops.at(-1) === location?.name || hops.at(-1) === node)) hops.pop()
    if (service && (hops.length || node)) {
        if (hops[0] === 'Общий маршрут' && (hops.length > 1 || node)) hops.shift()
        const head = hops[0]?.replace(/ \((по правилам|прокси устройства)\)$/, '')
        if (!head || (service !== head && !service.split(' / ').includes(head))) hops.unshift(service)
    }
    const outcome = flow.exit?.kind === 'direct' ? 'Напрямую' : flow.exit?.kind === 'reject' ? 'Блокировка' : ''
    if (outcome && hops.at(-1) !== outcome) hops.push(outcome)
    const hint = [flow.pool_current && 'Текущий выбор пула', location?.name].filter(Boolean).join(' · ')
    return <>
        <p className='mt-1 whitespace-pre-wrap break-words text-sm' title={flow.route.join(' → ')}>
            {hops.join(' → ')}{node && <>{hops.length > 0 && ' → '}<span title={hint || undefined}
                className={flow.pool_current ? 'underline decoration-dotted underline-offset-4' : undefined}>{node}</span></>}
            {!node && !hops.length && 'Ядро не сообщило маршрут'}
        </p>
        {(flow.rule || location?.source) && <p className='whitespace-pre-wrap break-words text-xs text-muted-foreground'>
            {flow.rule && 'Правило · ' + flow.rule}{flow.rule && location?.source && ' · '}{location?.source}
        </p>}
    </>
}

export function RouterActivity() {
    const [params, setParams] = useSearchParams()
    const device = params.get('device') ?? ''
    const [search, setSearch] = useState('')
    const [service, setService] = useState('')
    const [snapshot, setSnapshot] = useState<{ data: Activity; at: number; error?: string } | null>(null)
    const paused = snapshot !== null
    const [page, setPage] = useState(0)
    const known = useDevices().data?.devices ?? []
    const fullPath = usePanelSettings().data?.show_full_path !== false
    const query = useQuery({
        queryKey: ['router-activity'], queryFn: () => api.get<Activity>('/api/diagnostics'),
        enabled: !paused, refetchInterval: paused ? false : 3000, retry: false,
        gcTime: 0,
    })
    const data = snapshot?.data ?? query.data
    const updatedAt = snapshot?.at ?? query.dataUpdatedAt
    const error = paused ? snapshot.error : query.error?.message ?? data?.connections_error
    const sys = data?.system
    const flows = error ? [] : data?.connections ?? []
    const services = new Map(data?.services?.map(item => [item.id, item.name]))
    const devices = new Map<string, string>()
    for (const d of known) if (d.ip && d.active) devices.set(d.ip, d.name)
    for (const f of flows) if (f.device && !devices.has(f.device)) devices.set(f.device, '')
    if (device && !devices.has(device)) devices.set(device, '')
    const input = search.trim().toLowerCase()
    const filtered = flows.filter(f => {
        if ((device && f.device !== device) || (service && f.service_id !== service)) return false
        if (!input) return true
        const location = f.exit?.kind === 'server' ? f.exit : f.pool_current
        return [f.host, f.rule, f.service_id && services.get(f.service_id), ...f.route, location?.name, location?.source, location?.exit_country, fullPath ? location?.entry_country : '', serverPathDetail(location, fullPath)]
            .some(s => s?.toLowerCase().includes(input))
    })
    const pageSize = 25
    const last = Math.max(0, Math.ceil(filtered.length / pageSize) - 1)
    const current = Math.min(page, last)
    useEffect(() => { setPage(0) }, [search, device, service])
    return <>
        <RouterMetrics system={sys} history={data?.history}/>
        <Group title='Соединения по устройствам' footer='Пунктиром отмечен текущий выбор пула Xray.'>
            <div className='grid gap-3 py-3 sm:grid-cols-2 lg:grid-cols-3'>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Устройство
                    <select className='min-h-11 min-w-0 w-full rounded-xl bg-fill px-3 text-foreground' value={device} onChange={e => {
                        const next = new URLSearchParams(params)
                        if (e.target.value) next.set('device', e.target.value)
                        else next.delete('device')
                        setParams(next, {replace: true})
                    }}>
                        <option value=''>Все устройства</option>
                        {[...devices].sort((a,b) => (a[1] || a[0]).localeCompare(b[1] || b[0], 'ru')).map(([ip, name]) =>
                            <option key={ip} value={ip}>{name && name !== ip ? name + ' · ' + ip : ip}</option>)}
                    </select>
                </label>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Сервис
                    <select className='min-h-11 min-w-0 w-full rounded-xl bg-fill px-3 text-foreground' value={service} onChange={e => {
                        setService(e.target.value)
                        setSearch('')
                    }}>
                        <option value=''>Все сервисы</option>
                        {data?.services?.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                    </select>
                </label>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Поиск
                    <input type='search' placeholder='Домен, IP, правило или маршрут' value={search} onChange={e => {
                        setSearch(e.target.value)
                        setService('')
                    }}
                        className='min-h-11 min-w-0 rounded-xl bg-fill px-3 text-foreground' />
                </label>
            </div>
            <div className='flex flex-wrap items-center justify-between gap-x-3 py-1 text-sm'>
                <span>{paused ? 'Снимок' : 'Активные соединения'} · {filtered.length}
                    {updatedAt > 0 && <span className='text-muted-foreground'> · {clock.format(updatedAt)}</span>}
                </span>
                <button type='button' className='min-h-10 text-tint disabled:opacity-40' disabled={!data} onClick={() => setSnapshot(paused || !data ? null : { data, at: updatedAt, error })}>{paused ? 'Продолжить обновление' : 'Пауза'}</button>
            </div>
            {error ? <Row label='Соединения сейчас недоступны' hint={error} />
                : !data ? <Row label='Читаем соединения…' />
                : !filtered.length ? <Row label={search || device || service ? 'Подходящих соединений сейчас нет' : 'Сейчас нет активных соединений'} /> : null}
            {filtered.slice(current*pageSize, (current+1)*pageSize).map(f => {
                const name = devices.get(f.device)
                const destination = f.host.includes(':') && f.port ? '[' + f.host + ']' : f.host
                return <article key={f.id} className='min-w-0 py-3'>
                    <div className='flex flex-wrap items-baseline justify-between gap-x-3'>
                        <strong className='flex min-w-0 items-center gap-2 break-all text-[15px]'>{f.service_id && <ServiceLogo id={f.service_id} className='size-5' />}<span>{destination || 'Адрес неизвестен'}{f.port && ':' + f.port}</span></strong>
                        <span className='text-xs text-muted-foreground'>{f.network}</span>
                    </div>
                    <p className='break-words text-sm text-muted-foreground'>{name && name !== f.device ? name + ' · ' : ''}{f.device || 'Источник неизвестен'}</p>
                    <FlowRoute flow={f} service={f.service_id && services.get(f.service_id)} full={fullPath} />
                </article>
            })}
            {last > 0 && <div className='flex items-center justify-between py-1 text-sm'>
                <button className='min-h-11 text-tint disabled:opacity-40' disabled={!current} onClick={() => setPage(current-1)}>Назад</button>
                <span>{current+1} / {last+1}</span>
                <button className='min-h-11 text-tint disabled:opacity-40' disabled={current === last} onClick={() => setPage(current+1)}>Дальше</button>
            </div>}
        </Group>
    </>
}
