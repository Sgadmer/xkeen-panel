import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Group, Row } from '@/components/ios'
import { useDevices } from '@/hooks/usePanelData'
import { api } from '@/lib/api'

type Flow = { id: string; device: string; host: string; port?: string; network?: string; rule?: string; route: string[]; start: string }
type Activity = {
    system: { cpu_percent?: number; cores?: number; load?: number[]; ram_total_kib?: number; ram_used_kib?: number }
    connections: Flow[]
    connections_error?: string
}

const number = new Intl.NumberFormat('ru', { maximumFractionDigits: 1 })
const clock = new Intl.DateTimeFormat('ru', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

export function RouterActivity() {
    const [params, setParams] = useSearchParams()
    const device = params.get('device') ?? ''
    const [search, setSearch] = useState('')
    const [paused, setPaused] = useState(false)
    const [page, setPage] = useState(0)
    const known = useDevices().data?.devices ?? []
    const query = useQuery({
        queryKey: ['router-activity'], queryFn: () => api.get<Activity>('/api/diagnostics'),
        enabled: !paused, refetchInterval: paused ? false : 3000, retry: false,
        gcTime: 0,
    })
    const data = query.data
    const sys = data?.system
    const flows = data?.connections ?? []
    const devices = new Map<string, string>()
    for (const d of known) if (d.ip && d.active) devices.set(d.ip, d.name)
    for (const f of flows) if (f.device && !devices.has(f.device)) devices.set(f.device, '')
    if (device && !devices.has(device)) devices.set(device, '')
    const input = search.trim().toLowerCase()
    const filtered = flows.filter(f => (!device || f.device === device) &&
        (!input || [f.host, f.rule, ...f.route].some(s => s?.toLowerCase().includes(input))))
    const pageSize = 25
    const last = Math.max(0, Math.ceil(filtered.length / pageSize) - 1)
    const current = Math.min(page, last)
    useEffect(() => { setPage(0) }, [search, device])
    return <>
        <Group title='Нагрузка роутера'>
            <Row label='Процессор' detail={sys?.cpu_percent != null ? number.format(sys.cpu_percent) + ' %' : sys?.cores ? 'Замеряем…' : '—'} />
            <Row label='Оперативная память' detail={sys?.ram_total_kib ? Math.round((sys.ram_used_kib ?? 0) / 1024) + ' из ' + Math.round(sys.ram_total_kib / 1024) + ' МиБ' : '—'} />
            <Row label='Средняя нагрузка' hint='За 1, 5 и 15 минут' detail={sys?.load?.map(n => number.format(n)).join(' / ') ?? '—'} />
        </Group>
        <Group title='Соединения по устройствам' footer='Здесь видны активные соединения, прошедшие через Mihomo. Для HTTPS отображается домен или IP, путь страницы зашифрован. Если маршрут заканчивается пулом или профилем Xray, его внутренний выбор сервера Mihomo не видит.'>
            <div className='grid gap-3 py-3 sm:grid-cols-2'>
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
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Поиск
                    <input type='search' placeholder='Домен, IP, правило или маршрут' value={search} onChange={e => setSearch(e.target.value)}
                        className='min-h-11 min-w-0 rounded-xl bg-fill px-3 text-foreground' />
                </label>
            </div>
            <div className='flex flex-wrap items-center justify-between gap-x-3 py-1 text-sm'>
                <span>{paused ? 'Снимок' : 'Активные соединения'} · {filtered.length}
                    {query.dataUpdatedAt > 0 && <span className='text-muted-foreground'> · {clock.format(query.dataUpdatedAt)}</span>}
                </span>
                <button type='button' className='min-h-10 text-tint' onClick={() => setPaused(!paused)}>{paused ? 'Продолжить обновление' : 'Пауза'}</button>
            </div>
            {query.error || data?.connections_error ? <Row label='Соединения сейчас недоступны' hint={query.error?.message ?? data?.connections_error} />
                : !data ? <Row label='Читаем соединения…' />
                : !filtered.length ? <Row label={search || device ? 'Подходящих соединений сейчас нет' : 'Сейчас нет активных соединений'} /> : null}
            {filtered.slice(current*pageSize, (current+1)*pageSize).map(f => {
                const name = devices.get(f.device)
                const destination = f.host.includes(':') && f.port ? '[' + f.host + ']' : f.host
                return <article key={f.id} className='min-w-0 py-3'>
                    <div className='flex flex-wrap items-baseline justify-between gap-x-3'>
                        <strong className='min-w-0 break-all text-[15px]'>{destination || 'Адрес неизвестен'}{f.port && ':' + f.port}</strong>
                        <span className='text-xs text-muted-foreground'>{f.network}</span>
                    </div>
                    <p className='break-words text-sm text-muted-foreground'>{name && name !== f.device ? name + ' · ' : ''}{f.device || 'Источник неизвестен'}</p>
                    <p className='mt-1 break-words text-sm'>{f.route.length ? f.route.join(' → ') : 'Ядро не сообщило маршрут'}</p>
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
