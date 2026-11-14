import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Group, Row } from '@/components/ios'
import { useDevices } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { RouterMetrics, type RouterSample } from '@/components/routerMetrics'
import { ServiceLogo } from '@/components/serviceLogo'
import { countryName, withCountryFlag } from '@/lib/format'

type ServerLocation = { name?: string; country?: string; source?: string }
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

function LocationLine({ label, location }: { label: string; location: ServerLocation }) {
    const country = countryName(location.country)
    const title = location.name || country
    const showCountry = country && !title.toLocaleLowerCase('ru').includes(country.toLocaleLowerCase('ru'))
    return <p className='break-words text-sm'>
        <span className='text-muted-foreground'>{label} · </span>
        <span className='whitespace-pre-wrap font-medium'>{withCountryFlag(title, location.country)}</span>
        {showCountry && <span> · {country}</span>}
        {location.source && <span className='whitespace-pre-wrap text-muted-foreground'> · {location.source}</span>}
    </p>
}

function FlowExit({ flow }: { flow: Flow }) {
    const exit = flow.exit
    if (!exit) return null
    if (exit.kind === 'direct' || exit.kind === 'reject') {
        const how = exit.kind === 'direct' ? 'Напрямую' : 'Блокировка'
        return flow.route.at(-1) === how ? null : <p className='text-sm'>Выход · {how}</p>
    }
    if (exit.kind === 'server' && (exit.name || exit.country)) {
        return <LocationLine label='Локация соединения' location={exit} />
    }
    return <>
        {flow.pool_current && <LocationLine label='Выбор пула сейчас' location={flow.pool_current} />}
        <p className='text-xs text-muted-foreground'>Конечный сервер этого соединения неизвестен</p>
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
    const devices = new Map<string, string>()
    for (const d of known) if (d.ip && d.active) devices.set(d.ip, d.name)
    for (const f of flows) if (f.device && !devices.has(f.device)) devices.set(f.device, '')
    if (device && !devices.has(device)) devices.set(device, '')
    const input = search.trim().toLowerCase()
    const filtered = flows.filter(f => {
        if ((device && f.device !== device) || (service && f.service_id !== service)) return false
        if (!input) return true
        const location = f.exit?.kind === 'server' ? f.exit : f.pool_current
        return [f.host, f.rule, ...f.route, location?.name, location?.source, location?.country, countryName(location?.country)]
            .some(s => s?.toLowerCase().includes(input))
    })
    const pageSize = 25
    const last = Math.max(0, Math.ceil(filtered.length / pageSize) - 1)
    const current = Math.min(page, last)
    useEffect(() => { setPage(0) }, [search, device, service])
    return <>
        <RouterMetrics system={sys} history={data?.history}/>
        <Group title='Соединения по устройствам' footer='Для активных HTTPS-соединений Mihomo показывает домен или IP. Страна сервера указана по каталогу. «Выбор пула сейчас» может отличаться от сервера ранее открытого соединения.'>
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
                    <p className='mt-1 break-words text-sm'>{f.route.length ? f.route.join(' → ') : 'Ядро не сообщило маршрут'}</p>
                    <FlowExit flow={f} />
                    {f.rule && <p className='break-words text-xs text-muted-foreground'>Правило · {f.rule}</p>}
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
