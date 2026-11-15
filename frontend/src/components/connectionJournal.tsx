import { useEffect, useMemo, useRef, useState, type UIEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { IconSettings, IconWorld } from '@tabler/icons-react'
import { Group, Row, Segmented } from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { RouterMetrics, type RouterSample } from '@/components/routerMetrics'
import { ServiceLogo } from '@/components/serviceLogo'
import { TrafficHistorySettings } from '@/components/trafficHistorySettings'
import { useDevices } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { safeNotice } from '@/lib/subscription'
import { countryName, withCountryFlag } from '@/lib/format'
import { formatHistoryBytes, historySettingsKey, historySettingsPath, type HistoryPage, type HistorySettings, type JournalEntry, type JournalKind, type JournalLocation } from '@/lib/trafficHistory'

type Flow = {
    id: string; device: string; host: string; port?: string; network?: string; rule?: string
    service_id?: string; route: string[]; start: string
    exit?: JournalLocation
    pool_current?: { name?: string; country?: string; source?: string }
}
type GuardEvent = { id: string; at: string; service_id?: string; device?: string; host?: string; port?: string; network: string; reason: string; count: number }
type Activity = {
    system: RouterSample
    history?: RouterSample[]
    connections: Flow[]
    services?: { id: string; name: string }[]
    connections_error?: string
    guard?: { running: boolean; complete: boolean; error?: string; events: GuardEvent[] }
}
type ViewEntry = JournalEntry & { pool_current?: Flow['pool_current']; reason?: string }
type DeviceChoice = { id: string; ip?: string; name: string }

const clock = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const stamp = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const count = new Intl.NumberFormat('ru-RU')
const pageSize = 30
const selectClass = 'min-h-11 min-w-0 w-full rounded-xl bg-fill px-3 text-foreground'
const kindLabels: Record<JournalKind, string> = { connection: 'Соединение', kill_switch: 'Kill switch', quic: 'QUIC', error: 'Ошибка' }

function moment(value?: string) {
    const at = value ? Date.parse(value) : NaN
    return Number.isFinite(at) && at > 0 ? at : 0
}
function timeLabel(value: string, history = false) {
    const at = moment(value)
    return at ? (history ? stamp : clock).format(at) : '—'
}
function archiveRows(page?: HistoryPage): ViewEntry[] {
    return (page?.events ?? []).map(entry => ({ ...entry, host: entry.host || '', device: entry.device || '', route: entry.route ?? [] }))
}
function outcome(entry: ViewEntry) {
    if (entry.kind === 'kill_switch') return { label: 'Kill switch', className: 'bg-warning/10 text-warning' }
    if (entry.kind === 'quic') return { label: 'QUIC', className: 'bg-fill text-muted-foreground' }
    if (entry.kind === 'error') return { label: 'Ошибка', className: 'bg-destructive/10 text-destructive' }
    if (entry.exit?.kind === 'direct' || entry.route.includes('Напрямую')) return { label: 'Напрямую', className: 'bg-fill text-muted-foreground' }
    if (entry.exit?.kind === 'reject' || entry.route.includes('Блокировка')) return { label: 'Блокировка', className: 'bg-warning/10 text-warning' }
    const proxy = entry.exit?.kind === 'server' || !!entry.pool_current
    return { label: proxy ? 'VPN' : 'Маршрут', className: proxy ? 'bg-tint/10 text-tint' : 'bg-fill text-muted-foreground' }
}

function FlowRoute({ flow, service, compact = false }: { flow: ViewEntry; service?: string; compact?: boolean }) {
    const location = flow.exit?.kind === 'server' ? flow.exit : flow.pool_current
    const country = countryName(location?.country)
    const node = location && withCountryFlag(location.name || country, location.country)
    const hops = [...flow.route]
    if (node && flow.exit?.kind === 'server' && (hops.at(-1) === location?.name || hops.at(-1) === node)) hops.pop()
    if (service && (hops.length || node)) {
        if (hops[0] === 'Общий маршрут' && (hops.length > 1 || node)) hops.shift()
        const head = hops[0]?.replace(/ \((по правилам|прокси устройства)\)$/, '')
        if (!head || service !== head && !service.split(' / ').includes(head)) hops.unshift(service)
    }
    const label = flow.exit?.kind === 'direct' ? 'Напрямую' : flow.exit?.kind === 'reject' ? 'Блокировка' : ''
    if (label && hops.at(-1) !== label) hops.push(label)
    const reason = flow.kind === 'quic' ? 'QUIC заблокирован' : flow.kind === 'kill_switch' ?
        'Прямой выход запрещён' : flow.kind === 'error' ? 'Ошибка подключения' : 'Маршрут не сообщён'
    const hint = flow.pool_current ? ['Текущий выбор пула', country].filter(Boolean).join(' · ') : country
    return <>
        <p className={compact ? 'truncate text-[13px] leading-[18px]' : 'mt-1 whitespace-pre-wrap break-words text-sm'} title={[...hops, node].filter(Boolean).join(' → ')}>
            {hops.join(' → ')}{node && <>{hops.length > 0 && ' → '}<span title={hint || undefined}
                className={flow.pool_current ? 'underline decoration-dotted underline-offset-4' : undefined}>{node}</span></>}
            {!node && !hops.length && reason}
        </p>
        {(flow.rule || location?.source) && <p className={compact ? 'truncate text-xs leading-4 text-muted-foreground' : 'whitespace-pre-wrap break-words text-xs text-muted-foreground'}>
            {flow.rule && 'Правило · ' + flow.rule}{flow.rule && location?.source && ' · '}{location?.source}
        </p>}
    </>
}

function LogCard({ entry, service, history, onOpen }: { entry: ViewEntry; service?: string; history: boolean; onOpen: () => void }) {
    const status = outcome(entry)
    const host = entry.host.includes(':') && entry.port ? '[' + entry.host + ']' : entry.host
    const destination = host ? host + (entry.port ? ':' + entry.port : '') : kindLabels[entry.kind]
    return <article className='h-[88px] min-w-0 overflow-hidden border-b border-white/10 py-2' data-log-kind={entry.kind}>
        <div className='flex min-w-0 items-center gap-2 leading-5'>
            <button type='button' onClick={onOpen} aria-label={`Подробнее: ${destination}`} title={destination}
                className='flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left text-[14px] font-semibold focus-visible:rounded focus-visible:outline-2 focus-visible:outline-tint'>
                {entry.service_id ? <ServiceLogo id={entry.service_id} className='size-4 shrink-0' /> : <IconWorld aria-hidden className='size-4 shrink-0 text-muted-foreground' />}
                <span className='truncate'>{destination}</span>
            </button>
            <span className={'shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-4 ' + status.className}>{status.label}</span>
            {(entry.count ?? 1) > 1 && <span className='shrink-0 text-xs tabular-nums text-muted-foreground'>×{count.format(entry.count!)}</span>}
            <time dateTime={entry.at} className='shrink-0 text-[11px] tabular-nums text-muted-foreground'>{timeLabel(entry.at, history)}</time>
        </div>
        <p className='truncate text-xs leading-4 text-muted-foreground'>
            {entry.device_name && entry.device_name !== entry.device ? entry.device_name + ' · ' : ''}{entry.device || 'Устройство'}{entry.network && ' · ' + entry.network.toUpperCase()}
        </p>
        <FlowRoute flow={entry} service={service} compact />
    </article>
}

function LogDetails({ entry, service, onClose }: { entry: ViewEntry | null; service?: string; onClose: () => void }) {
    return <Sheet open={entry !== null} onClose={onClose} title='Событие журнала' closeLabel='Закрыть'>
        {entry && <>
            <Group>
                <Row label='Адрес' hint={entry.host + (entry.port ? ':' + entry.port : '')} />
                <Row label='Время' detail={timeLabel(entry.at, true)} />
                <Row label='Устройство' hint={[entry.device_name, entry.device].filter(Boolean).join(' · ')} />
                {service && <Row label='Сервис' detail={service} />}
                <Row label='Событие' detail={kindLabels[entry.kind]} />
                {entry.network && <Row label='Протокол' detail={entry.network.toUpperCase()} />}
                {(entry.count ?? 1) > 1 && <Row label='Повторных попыток' detail={count.format(entry.count!)} />}
            </Group>
            <Group title='Маршрут'>
                <div className='py-3'><FlowRoute flow={entry} service={service} /></div>
            </Group>
            {entry.kind === 'quic' && <p className='px-3 text-sm text-muted-foreground'>Роутер остановил QUIC. Приложение может перейти на обычное HTTPS-соединение. Это отдельное правило протокола, а не отказ VPN-сервера.</p>}
            {entry.kind === 'kill_switch' && <p className='px-3 text-sm text-warning'>Не удалось использовать защищённый VPN-маршрут. Прямой выход для этого запроса запрещён.</p>}
        </>}
    </Sheet>
}

export function ConnectionJournal() {
    const [params, setParams] = useSearchParams()
    const device = params.get('device') ?? ''
    const [search, setSearch] = useState('')
    const [service, setService] = useState('')
    const [kind, setKind] = useState<JournalKind | ''>('')
    const [mode, setMode] = useState<'live' | 'history'>(() => params.get('view') === 'history' ? 'history' : 'live')
    const [paused, setPaused] = useState(false)
    const [frozen, setFrozen] = useState<ViewEntry[] | null>(null)
    const [frozenAt, setFrozenAt] = useState(0)
    const [page, setPage] = useState(0)
    const [cursors, setCursors] = useState([''])
    const [settingsOpen, setSettingsOpen] = useState(false)
    const [details, setDetails] = useState<ViewEntry | null>(null)
    const baseline = useRef<Set<string> | null>(null)
    const scroller = useRef<HTMLDivElement>(null)
    const known = useDevices().data?.devices ?? []
    const activity = useQuery({ queryKey: ['router-activity'], queryFn: () => api.get<Activity>('/api/diagnostics'), refetchInterval: 3000, retry: false, gcTime: 0 })
    const settings = useQuery({ queryKey: historySettingsKey, queryFn: () => api.get<HistorySettings>(historySettingsPath), refetchInterval: 15000, retry: false })
    const supported = settings.data?.supported !== false
    const enabled = settings.data?.enabled === true && supported
    const data = activity.data
    const services = new Map(data?.services?.map(item => [item.id, item.name]))
    const sourceIP = new Map(known.filter(item => item.ip).map(item => [item.ip!, item]))
    const query = new URLSearchParams({ limit: String(pageSize) })
    if (device) query.set('device', device)
    if (service) query.set('service', service)
    if (kind) query.set('kind', kind)
    if (search.trim()) query.set('q', search.trim())
    const filterKey = query.toString()
    const cursor = cursors.at(-1) || ''
    const latestHistory = useQuery({
        queryKey: ['traffic-history', filterKey, 'latest'], queryFn: () => api.get<HistoryPage>('/api/traffic-history?' + filterKey),
        enabled: enabled && mode === 'history', refetchInterval: enabled && mode === 'history' ? 3000 : false, retry: false,
    })
    const olderHistory = useQuery({
        queryKey: ['traffic-history', filterKey, cursor], queryFn: () => api.get<HistoryPage>('/api/traffic-history?' + filterKey + '&cursor=' + encodeURIComponent(cursor)),
        enabled: enabled && mode === 'history' && !!cursor, retry: false,
    })
    const response = cursor ? olderHistory.data : latestHistory.data
    const input = search.trim().toLowerCase()
    const liveRows: ViewEntry[] = [
        ...(data?.connections ?? []).map<ViewEntry>(flow => {
            const owner = sourceIP.get(flow.device)
            return { ...flow, id: 'flow:' + flow.id, at: flow.start, kind: 'connection' as const, device_id: owner?.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + flow.device, device_name: owner?.name }
        }),
        ...(data?.guard?.events ?? []).map<ViewEntry>(event => {
            const ip = event.device || '', owner = sourceIP.get(ip)
            return { ...event, id: 'guard:' + event.id, device: ip, device_id: owner?.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + ip, device_name: owner?.name,
                kind: event.reason === 'protocol_guard' ? 'quic' as const : 'kill_switch' as const, host: event.host || '', route: [] }
        }),
    ].filter(entry => {
        if (device && entry.device !== device && entry.device_id !== device) return false
        if (service && entry.service_id !== service || kind && entry.kind !== kind) return false
        return !input || [entry.host, entry.device, entry.device_name, entry.rule, entry.service_id && services.get(entry.service_id), ...entry.route,
            entry.exit?.name, entry.exit?.source, entry.exit?.country, countryName(entry.exit?.country)].some(value => value?.toLowerCase().includes(input))
    }).sort((a, b) => moment(b.at) - moment(a.at) || a.id.localeCompare(b.id))
    const sourceRows: ViewEntry[] = mode === 'live' ? liveRows : enabled ? archiveRows(response) : []
    const newestRows: ViewEntry[] = mode === 'live' ? liveRows : enabled ? archiveRows(latestHistory.data) : []
    const rows = frozen ?? sourceRows
    const visibleRows = mode === 'live' ? rows.slice(page * pageSize, (page + 1) * pageSize) : rows
    const newCount = baseline.current ? newestRows.filter(entry => !baseline.current!.has(entry.id)).length : 0
    const newerBeyondPage = mode === 'history' && newCount === pageSize && latestHistory.data?.has_more
    const deviceChoices = useMemo(() => {
        const choices = new Map<string, DeviceChoice>()
        for (const owner of known) if (owner.ip || owner.mac) {
            const id = owner.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + owner.ip
            choices.set(id, { id, ip: owner.ip, name: owner.name || owner.ip || 'Устройство' })
        }
        for (const owner of [...latestHistory.data?.devices ?? [], ...response?.devices ?? []]) {
            choices.set(owner.id, { id: owner.id, ip: owner.ip, name: owner.name || owner.ip || 'Устройство' })
        }
        for (const entry of [...liveRows, ...response?.events ?? []]) {
            const id = entry.device_id || 'ip:' + entry.device
            if (!choices.has(id)) choices.set(id, { id, ip: entry.device, name: entry.device_name || entry.device || 'Устройство' })
        }
        if (device && !choices.has(device)) {
            const owner = known.find(item => item.ip === device)
            choices.set(device, { id: device, ip: owner?.ip, name: owner?.name || device })
        }
        return [...choices.values()].sort((a, b) => a.name.localeCompare(b.name, 'ru'))
    }, [known, latestHistory.data?.devices, response, device, liveRows])
    const historyError = (cursor ? olderHistory.error : latestHistory.error)?.message
    const error = mode === 'history' ? historyError : activity.error?.message ?? data?.connections_error
    const loading = mode === 'live' ? activity.isPending : enabled && (cursor ? olderHistory.isPending : latestHistory.isPending)
    const updatedAt = mode === 'live' ? activity.dataUpdatedAt : cursor ? olderHistory.dataUpdatedAt : latestHistory.dataUpdatedAt
    const displayedAt = frozen !== null ? frozenAt : updatedAt
    const freeze = () => {
        if (!baseline.current) baseline.current = new Set(newestRows.map(entry => entry.id))
        if (frozen === null) { setFrozen(sourceRows); setFrozenAt(updatedAt) }
    }
    const newest = () => {
        baseline.current = null
        setFrozen(null)
        setFrozenAt(0)
        setPaused(false)
        setPage(0)
        setCursors([''])
        if (scroller.current) scroller.current.scrollTop = 0
    }
    useEffect(() => { newest() }, [device, search, service, kind, mode, enabled])
    const onScroll = (event: UIEvent<HTMLDivElement>) => {
        if (event.currentTarget.scrollTop > 8 && frozen === null && !cursor) freeze()
    }
    const nextPage = () => {
        if (!baseline.current) baseline.current = new Set(newestRows.map(entry => entry.id))
        if (mode === 'history' && response?.has_more && response.next_cursor) {
            setFrozen(null)
            setCursors(value => [...value, response.next_cursor!])
        } else if (mode === 'live') {
            if (frozen === null) { setFrozen(sourceRows); setFrozenAt(updatedAt) }
            setPage(value => value + 1)
        }
        if (scroller.current) scroller.current.scrollTop = 0
    }
    const previousPage = () => {
        if (mode === 'history' && cursors.length === 2) { newest(); return }
        if (mode === 'history') { setFrozen(null); setCursors(value => value.slice(0, -1)) }
        else setPage(value => Math.max(0, value - 1))
        if (scroller.current) scroller.current.scrollTop = 0
    }
    const canPrevious = mode === 'history' ? cursors.length > 1 : page > 0
    const canNext = mode === 'history' ? !!response?.has_more && !!response?.next_cursor : (page + 1) * pageSize < rows.length
    return <>
        <RouterMetrics system={data?.system} history={data?.history} />
        <Group title='Журнал соединений' footer={mode === 'history' ? 'Маршрут сохранён на момент события. Записи старше 24 часов удаляются; при достижении лимитов история может быть короче.' : 'Сейчас показаны активные соединения и недавние события защиты. Пунктиром отмечен текущий выбор пула Xray.'}>
            <div className='flex flex-wrap items-center justify-between gap-3 py-3'>
                <Segmented label='Период журнала' options={[{ value: 'live', label: 'Сейчас' }, { value: 'history', label: 'Последние 24 часа' }]} value={mode} onChange={setMode} />
                <button type='button' onClick={() => setSettingsOpen(true)} className='flex min-h-10 cursor-pointer items-center gap-1.5 text-sm text-tint'><IconSettings aria-hidden className='size-4' />Настройки истории</button>
            </div>
            <div className='grid gap-3 py-3 sm:grid-cols-2 xl:grid-cols-4'>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Устройство
                    <select className={selectClass} value={device} onChange={event => {
                        const next = new URLSearchParams(params)
                        if (event.target.value) next.set('device', event.target.value)
                        else next.delete('device')
                        setParams(next, { replace: true })
                    }}>
                        <option value=''>Все устройства</option>
                        {deviceChoices.map(owner => <option key={owner.id} value={owner.id}>{owner.name}{owner.ip && owner.ip !== owner.name ? ' · ' + owner.ip : ''}</option>)}
                    </select>
                </label>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Сервис
                    <select className={selectClass} value={service} onChange={event => { setService(event.target.value); setSearch('') }}>
                        <option value=''>Все сервисы</option>
                        {data?.services?.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                    </select>
                </label>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>События
                    <select className={selectClass} value={kind} onChange={event => setKind(event.target.value as JournalKind | '')}>
                        <option value=''>Все события</option>
                        <option value='connection'>Соединения</option><option value='kill_switch'>Kill switch</option><option value='quic'>QUIC</option><option value='error'>Ошибки</option>
                    </select>
                </label>
                <label className='grid min-w-0 gap-1 text-sm text-muted-foreground'>Поиск
                    <input type='search' placeholder='Домен, IP, правило или маршрут' value={search} onChange={event => { setSearch(event.target.value); setService('') }} className={selectClass} />
                </label>
            </div>
            <div className='flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 py-1 text-sm'>
                <span>{mode === 'history' ? 'История' : 'Сейчас'} · {count.format(rows.length)}{displayedAt > 0 && <span className='text-muted-foreground'> · {clock.format(displayedAt)}</span>}{paused && ' · пауза'}</span>
                <div className='flex items-center gap-3'>
                    {(newCount > 0 || frozen !== null || !!cursor || page > 0) && <button type='button' onClick={newest} className='min-h-10 cursor-pointer text-tint'>{newCount ? `Новых событий: ${newCount}${newerBeyondPage ? '+' : ''}` : 'К новым событиям'}</button>}
                    <button type='button' disabled={loading || mode === 'history' && !enabled} onClick={() => { if (paused) newest(); else { freeze(); setPaused(true) } }} className='min-h-10 cursor-pointer text-tint disabled:opacity-40'>{paused ? 'Продолжить' : 'Пауза'}</button>
                </div>
            </div>
            {mode === 'live' && data?.guard && (!data.guard.running || !data.guard.complete) && <p role='status' className='py-2 text-xs text-warning'>{data.guard.error || 'Наблюдение за событиями защиты сейчас неполное.'}</p>}
            {mode === 'history' && enabled && settings.data && <p className='py-2 text-xs text-muted-foreground'>
                На диске · {count.format(settings.data.events || 0)} записей · {formatHistoryBytes(settings.data.bytes)}{settings.data.oldest_at && ' · с ' + timeLabel(settings.data.oldest_at, true)}
                {!!settings.data.dropped && <span className='text-warning'> · пропущено {count.format(settings.data.dropped)}</span>}
            </p>}
            <div ref={scroller} onScroll={onScroll} role='region' aria-label='Записи журнала' tabIndex={0}
                className='h-[880px] max-h-[70dvh] min-h-44 overflow-y-auto overscroll-contain [scrollbar-gutter:stable] sm:max-h-none'>
                {mode === 'history' && !enabled ? <div className='py-6 text-sm'>
                    <p className='font-medium'>{supported ? 'История на диске выключена' : 'История на диске недоступна'}</p>
                    <p className='mt-1 max-w-xl text-muted-foreground'>{supported ? 'Чтобы видеть закрытые соединения за последние сутки, выберите внешний диск и папку в настройках истории.' : safeNotice(settings.data?.error || '', 'На этой модели доступен текущий журнал без записи истории на диск.')}</p>
                    <button type='button' onClick={() => setSettingsOpen(true)} className='mt-2 min-h-11 cursor-pointer text-tint'>Настроить историю</button>
                    {settings.error && <p role='alert' className='mt-2 text-destructive'>Настройки истории сейчас недоступны.</p>}
                </div> : error ? <Row label='Журнал сейчас недоступен' hint={error} /> : loading ? <Row label='Читаем журнал…' /> : !visibleRows.length ?
                    <Row label={device || service || search || kind ? 'Подходящих записей нет' : 'Записей пока нет'} /> : null}
                {!(mode === 'history' && !enabled) && visibleRows.map(entry => <LogCard key={entry.id} entry={entry} service={entry.service_id && services.get(entry.service_id)} history={mode === 'history'} onOpen={() => { freeze(); setDetails(entry) }} />)}
            </div>
            {(canPrevious || canNext) && <div className='flex items-center justify-between gap-3 py-1 text-sm'>
                <button type='button' disabled={!canPrevious || loading || paused} onClick={previousPage} className='min-h-11 cursor-pointer text-tint disabled:opacity-40'>Назад</button>
                <span className='text-muted-foreground'>Страница {mode === 'history' ? cursors.length : page + 1}</span>
                <button type='button' disabled={!canNext || loading || paused} onClick={nextPage} className='min-h-11 cursor-pointer text-tint disabled:opacity-40'>Дальше</button>
            </div>}
        </Group>
        <TrafficHistorySettings open={settingsOpen} onClose={() => setSettingsOpen(false)} />
        <LogDetails entry={details} service={details?.service_id && services.get(details.service_id)} onClose={() => setDetails(null)} />
    </>
}
