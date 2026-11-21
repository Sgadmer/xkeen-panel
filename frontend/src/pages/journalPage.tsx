import { useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { IconBookmark, IconDownload, IconPlayerRecord, IconPlayerStop, IconSettings, IconTrash, IconWorld, IconX } from '@tabler/icons-react'
import { Group, PageTitle, Row, Segmented } from '@/components/ios'
import { LogCard, LogDetails, destination, kindLabels, moment, routeText, timeLabel, type ViewEntry } from '@/components/journalEntries'
import { ServiceLogo } from '@/components/serviceLogo'
import { Sheet } from '@/components/sheet'
import { TrafficHistorySettings } from '@/components/trafficHistorySettings'
import { useDevices } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { countryName, plural } from '@/lib/format'
import {
    defaultFilters, filtersFromParams, historyQuery, paramsFromFilters, rememberFilters, rememberedFilters, sameFilters, saveTextFile,
    type JournalFilters, type JournalPreset, type JournalSite, type JournalSource,
} from '@/lib/journal'
import { historySettingsKey, historySettingsPath, type HistoryPage, type HistorySettings, type JournalKind, type JournalLocation } from '@/lib/trafficHistory'

type Flow = {
    id: string; device: string; host: string; port?: string; network?: string; rule?: string
    service_id?: string; route: string[]; start: string
    exit?: JournalLocation
    pool_current?: { name?: string; country?: string; source?: string }
}
type GuardEvent = { id: string; at: string; service_id?: string; device?: string; host?: string; port?: string; network: string; reason: string; count: number }
type Live = {
    connections: Flow[]
    services?: { id: string; name: string }[]
    connections_error?: string
    guard?: { running: boolean; complete: boolean; error?: string; events: GuardEvent[] }
}
type Capture = { device: string; since: string; until?: string }

const count = new Intl.NumberFormat('ru-RU')
const pageSize = 50
const field = 'min-h-11 min-w-0 w-full rounded-xl bg-fill px-3 text-foreground outline-none focus:ring-1 focus:ring-tint'
const sourceLabels: Record<JournalSource, string> = { live: 'Сейчас', recent: 'Недавние', history: 'Сутки' }
const CAPTURE = 'xkeen.journal.capture.v1'

function useTabVisible() {
    const [visible, setVisible] = useState(() => document.visibilityState !== 'hidden')
    useEffect(() => {
        const update = () => setVisible(document.visibilityState !== 'hidden')
        document.addEventListener('visibilitychange', update)
        return () => document.removeEventListener('visibilitychange', update)
    }, [])
    return visible
}

function storedCapture(): Capture | null {
    try {
        const value = JSON.parse(sessionStorage.getItem(CAPTURE) || 'null')
        return value && typeof value.device === 'string' && typeof value.since === 'string' ? value : null
    } catch {
        return null
    }
}

export function JournalPage() {
    const qc = useQueryClient()
    const navigate = useNavigate()
    const visible = useTabVisible()
    const [params, setParams] = useSearchParams()
    const filters = useMemo(() => filtersFromParams(params), [params])
    const [searchDraft, setSearchDraft] = useState(filters.search)
    const [paused, setPaused] = useState(false)
    const [details, setDetails] = useState<ViewEntry | null>(null)
    const [settingsOpen, setSettingsOpen] = useState(false)
    const [presetSheet, setPresetSheet] = useState<'save' | 'manage' | null>(null)
    const [presetName, setPresetName] = useState('')
    const [capture, setCaptureState] = useState<Capture | null>(storedCapture)
    const [copied, setCopied] = useState(false)
    const restored = useRef(false)

    const update = (patch: Partial<JournalFilters>) => {
        const next = { ...filters, ...patch }
        if (patch.view === 'sites') next.source = 'recent'
        if (patch.source && patch.source !== 'recent') next.view = 'list'
        rememberFilters(next)
        setParams(paramsFromFilters(next), { replace: true })
        setPaused(false)
    }
    const setCapture = (value: Capture | null) => {
        setCaptureState(value)
        try {
            if (value) sessionStorage.setItem(CAPTURE, JSON.stringify(value))
            else sessionStorage.removeItem(CAPTURE)
        } catch {
            // The recording still lives until the page is closed.
        }
    }

    // Opened without filters in the address: continue where the journal was left.
    useEffect(() => {
        if (restored.current) return
        restored.current = true
        if ([...params.keys()].length > 0) {
            rememberFilters(filters)
            return
        }
        const saved = rememberedFilters()
        if (saved && !sameFilters(saved, defaultFilters)) setParams(paramsFromFilters(saved), { replace: true })
    }, [params, filters, setParams])
    useEffect(() => { setSearchDraft(filters.search) }, [filters.search])
    useEffect(() => {
        if (searchDraft.trim() === filters.search.trim()) return
        const timer = window.setTimeout(() => update({ search: searchDraft }), 350)
        return () => window.clearTimeout(timer)
        // Typing is what starts the timer; the filters it reads are current by then.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [searchDraft])

    // A recording narrows the short journal to one device and a time window.
    const active: JournalFilters = capture ? { ...filters, source: 'recent', device: capture.device } : filters
    const window_ = capture ? { since: capture.since, before: capture.until } : undefined
    const frozen = paused || !!capture?.until

    const known = useDevices().data?.devices ?? []
    const settings = useQuery({ queryKey: historySettingsKey, queryFn: () => api.get<HistorySettings>(historySettingsPath), refetchInterval: 15000, retry: false })
    const meta = useQuery({ queryKey: ['journal-meta'], queryFn: () => api.get<Live>('/api/diagnostics?connections=0&load=0'), staleTime: Infinity })
    const recentOn = settings.data?.recent_enabled !== false
    const diskOn = settings.data?.enabled === true && settings.data?.supported !== false
    const sourceReady = active.source === 'live' || (active.source === 'recent' ? recentOn : diskOn)

    const live = useQuery({
        queryKey: ['journal-live'], queryFn: () => api.get<Live>('/api/diagnostics?load=0'),
        enabled: active.source === 'live', refetchInterval: frozen || !visible ? false : 3000, retry: false, gcTime: 0,
    })
    const filterKey = historyQuery(active, pageSize, window_)
    const pages = useInfiniteQuery({
        queryKey: ['journal', filterKey],
        queryFn: ({ pageParam }) => api.get<HistoryPage>('/api/traffic-history?' + filterKey + (pageParam ? '&cursor=' + encodeURIComponent(pageParam) : '')),
        initialPageParam: '',
        getNextPageParam: last => last.has_more && last.next_cursor ? last.next_cursor : undefined,
        enabled: active.source !== 'live' && active.view === 'list' && sourceReady,
        // Only the first page follows new records; a longer list waits for a tap.
        refetchInterval: query => !frozen && visible && (query.state.data?.pages.length ?? 0) <= 1 ? 3000 : false,
        retry: false,
    })
    const sites = useQuery({
        queryKey: ['journal-sites', filterKey],
        queryFn: () => api.get<{ sites: JournalSite[] }>('/api/traffic-history/sites?' + filterKey),
        enabled: active.view === 'sites' && sourceReady, refetchInterval: frozen || !visible ? false : 5000, retry: false,
    })
    const enableRecent = useMutation({
        mutationFn: () => api.put<HistorySettings>(historySettingsPath, { recent_off: false }),
        onSuccess: data => qc.setQueryData(historySettingsKey, data),
    })
    const presets = useQuery({ queryKey: ['journal-presets'], queryFn: () => api.get<{ presets: JournalPreset[] }>('/api/journal/presets').then(data => data.presets ?? []) })
    const savePresets = useMutation({
        mutationFn: (list: JournalPreset[]) => api.put<{ presets: JournalPreset[] }>('/api/journal/presets', { presets: list }),
        onSuccess: data => { qc.setQueryData(['journal-presets'], data.presets); setPresetName(''); if (presetSheet === 'save') setPresetSheet(null) },
    })

    const services = new Map((meta.data?.services ?? live.data?.services ?? []).map(item => [item.id, item.name]))
    const sourceIP = new Map(known.filter(item => item.ip).map(item => [item.ip!, item]))
    const input = active.search.trim().toLowerCase()
    const liveRows: ViewEntry[] = active.source !== 'live' ? [] : [
        ...(live.data?.connections ?? []).map<ViewEntry>(flow => {
            const owner = sourceIP.get(flow.device)
            return { ...flow, id: 'flow:' + flow.id, at: flow.start, kind: 'connection' as const, device_id: owner?.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + flow.device, device_name: owner?.name }
        }),
        ...(live.data?.guard?.events ?? []).map<ViewEntry>(event => {
            const ip = event.device || '', owner = sourceIP.get(ip)
            return {
                ...event, id: 'guard:' + event.id, device: ip, device_id: owner?.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + ip, device_name: owner?.name,
                kind: event.reason === 'protocol_guard' ? 'quic' as const : 'kill_switch' as const, host: event.host || '', route: [],
            }
        }),
    ].filter(entry => {
        if (active.device && entry.device !== active.device && entry.device_id !== active.device) return false
        if (active.service && entry.service_id !== active.service || active.kind && entry.kind !== active.kind) return false
        return !input || [entry.host, entry.device, entry.device_name, entry.rule, entry.service_id && services.get(entry.service_id), ...entry.route,
            entry.exit?.name, entry.exit?.source, countryName(entry.exit?.country)].some(value => value?.toLowerCase().includes(input))
    }).sort((a, b) => moment(b.at) - moment(a.at) || a.id.localeCompare(b.id))
    const storedRows: ViewEntry[] = (pages.data?.pages ?? []).flatMap(page => page.events).map(entry => ({ ...entry, host: entry.host || '', device: entry.device || '', route: entry.route ?? [] }))
    const rows = active.source === 'live' ? liveRows : storedRows
    const siteRows = sites.data?.sites ?? []

    const deviceChoices = useMemo(() => {
        const choices = new Map<string, { id: string; name: string; ip?: string }>()
        for (const owner of known) if (owner.ip || owner.mac) {
            const id = owner.mac ? 'mac:' + owner.mac.toLowerCase() : 'ip:' + owner.ip
            choices.set(id, { id, ip: owner.ip, name: owner.name || owner.ip || 'Устройство' })
        }
        for (const owner of pages.data?.pages[0]?.devices ?? []) {
            if (!choices.has(owner.id)) choices.set(owner.id, { id: owner.id, ip: owner.ip, name: owner.name || owner.ip || 'Устройство' })
        }
        if (active.device && !choices.has(active.device)) choices.set(active.device, { id: active.device, name: active.device.replace(/^(mac|ip):/, '') })
        return [...choices.values()].sort((a, b) => a.name.localeCompare(b.name, 'ru'))
    }, [known, pages.data, active.device])
    const deviceName = (id: string) => deviceChoices.find(item => item.id === id)?.name ?? id.replace(/^(mac|ip):/, '')

    const loading = !sourceReady ? false : active.view === 'sites' ? sites.isPending : active.source === 'live' ? live.isPending : pages.isPending
    const failure = active.view === 'sites' ? sites.error?.message : active.source === 'live' ? live.error?.message ?? live.data?.connections_error : pages.error?.message
    const incomplete = settings.data?.error && (active.source !== 'live' || live.data?.guard && !live.data.guard.complete)
    const filtered = !!(active.device || active.service || active.kind || active.search.trim())
    const total = active.view === 'sites' ? siteRows.length : rows.length

    const activePreset = (presets.data ?? []).find(item => sameFilters(filters, item))
    const exportRows = () => {
        const head = active.view === 'sites'
            ? ['Адрес', 'Сервис', 'Всего', 'VPN', 'Напрямую', 'Блокировок', 'Ошибок', 'Последний раз']
            : ['Время', 'Устройство', 'Адрес', 'Событие', 'Маршрут', 'Правило']
        const body = active.view === 'sites'
            ? siteRows.map(site => [site.host, site.service_id ? services.get(site.service_id) ?? site.service_id : '', site.count, site.vpn, site.direct, site.blocked, site.errors, timeLabel(site.last_at, true)])
            : rows.map(entry => [timeLabel(entry.at, true), [entry.device_name, entry.device].filter(Boolean).join(' '), destination(entry), kindLabels[entry.kind], routeText(entry, entry.service_id && services.get(entry.service_id)), entry.rule ?? ''])
        saveTextFile(`xkeen-journal-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.tsv`, [head, ...body].map(line => line.join('\t')).join('\n'))
    }
    const copyEntry = (entry: ViewEntry) => {
        const text = [timeLabel(entry.at, true), [entry.device_name, entry.device].filter(Boolean).join(' '), destination(entry), kindLabels[entry.kind], routeText(entry, entry.service_id && services.get(entry.service_id))].join(' · ')
        void navigator.clipboard?.writeText(text).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 2000) }, () => {})
    }

    return <>
        <PageTitle title='Журнал' subtitle='Куда обращаются устройства и каким путём идёт трафик'
            action={<button type='button' onClick={() => setSettingsOpen(true)} aria-label='Настройки журнала' className='glass glass-tint flex min-h-11 shrink-0 cursor-pointer items-center gap-2 rounded-full px-4 text-[15px]'><IconSettings aria-hidden className='size-5' /><span className='max-sm:hidden'>Настройки</span></button>} />

        <div className='flex min-w-0 items-center gap-2 overflow-x-auto [scrollbar-width:none] empty:hidden' aria-label='Шаблоны журнала'>
            {(presets.data ?? []).map(preset => <button key={preset.id} type='button' aria-pressed={preset.id === activePreset?.id}
                onClick={() => { setCapture(null); update({ ...defaultFilters, ...preset, device: preset.device ?? '', service: preset.service ?? '', kind: preset.kind ?? '', search: preset.search ?? '' }) }}
                className={'min-h-10 shrink-0 cursor-pointer rounded-full px-4 text-[15px] ' + (preset.id === activePreset?.id ? 'bg-primary font-semibold text-primary-foreground' : 'bg-card')}>{preset.name}</button>)}
            {!activePreset && (filtered || filters.view === 'sites' || filters.source !== defaultFilters.source) && <button type='button' onClick={() => { savePresets.reset(); setPresetSheet('save') }}
                className='flex min-h-10 shrink-0 cursor-pointer items-center gap-1.5 rounded-full border border-dashed border-white/20 px-4 text-[15px] text-tint'><IconBookmark aria-hidden className='size-4' />Сохранить как шаблон</button>}
            {(presets.data?.length ?? 0) > 0 && <button type='button' onClick={() => { savePresets.reset(); setPresetSheet('manage') }} className='min-h-10 shrink-0 cursor-pointer px-2 text-[15px] text-muted-foreground'>Изменить</button>}
        </div>

        <div className='flex flex-wrap items-center gap-3'>
            <div className='min-w-0 flex-1 basis-72'><Segmented label='Период журнала' options={(['live', 'recent', 'history'] as JournalSource[]).map(value => ({ value, label: sourceLabels[value] }))}
                value={active.source} onChange={source => { if (!capture) update({ source }) }} /></div>
            <div className='basis-56'><Segmented label='Вид журнала' options={[{ value: 'list', label: 'Лента' }, { value: 'sites', label: 'По сайтам' }]}
                value={active.view} onChange={view => update({ view })} /></div>
        </div>

        <div className='grid grid-cols-2 gap-2 sm:gap-3 xl:grid-cols-4'>
            <select aria-label='Устройство' className={field} value={active.device} disabled={!!capture} onChange={event => update({ device: event.target.value })}>
                <option value=''>Все устройства</option>
                {deviceChoices.map(owner => <option key={owner.id} value={owner.id}>{owner.name}{owner.ip && owner.ip !== owner.name ? ' · ' + owner.ip : ''}</option>)}
            </select>
            <select aria-label='Сервис' className={field} value={active.service} onChange={event => update({ service: event.target.value })}>
                <option value=''>Все сервисы</option>
                {[...services].map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
            <select aria-label='События' className={field} value={active.kind} onChange={event => update({ kind: event.target.value as JournalKind | '' })}>
                <option value=''>Все события</option>
                <option value='connection'>Соединения</option><option value='kill_switch'>Kill switch</option><option value='quic'>QUIC</option><option value='error'>Ошибки</option>
            </select>
            <div className='relative'>
                <input type='search' aria-label='Поиск' placeholder='Домен, IP, правило или сервер' value={searchDraft} onChange={event => setSearchDraft(event.target.value)} className={field} />
            </div>
        </div>

        {capture && <div role='status' className='flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-card border border-destructive/30 bg-destructive/5 px-4 py-2 text-[15px]'>
            <span className='min-w-0'>{capture.until ? 'Запись' : 'Идёт запись'} · {deviceName(capture.device)} · с {timeLabel(capture.since)}{capture.until && ' до ' + timeLabel(capture.until)}</span>
            <span className='flex gap-4'>
                {!capture.until && <button type='button' onClick={() => setCapture({ ...capture, until: new Date().toISOString() })} className='flex min-h-11 cursor-pointer items-center gap-1.5 font-semibold text-destructive'><IconPlayerStop aria-hidden className='size-4' />Остановить</button>}
                <button type='button' onClick={() => setCapture(null)} className='min-h-11 cursor-pointer text-tint'>{capture.until ? 'Закрыть запись' : 'Отменить'}</button>
            </span>
        </div>}

        <Group footer={active.source === 'live' ? 'Открытые сейчас соединения и недавние срабатывания защиты.'
            : active.source === 'recent' ? `Последние записи из памяти роутера: до ${count.format(settings.data?.recent_events ?? 5000)} штук, не старше ${settings.data?.recent_minutes ?? 60} минут. После перезапуска панели журнал начинается заново.`
                : 'Записи с внешнего диска за последние 24 часа.'}>
            <div className='flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 py-1 text-sm'>
                <span>{sourceLabels[active.source]} · {count.format(total)}{active.view === 'list' && active.source !== 'live' && pages.hasNextPage ? '+' : ''} {active.view === 'sites' ? plural(total, 'адрес', 'адреса', 'адресов') : plural(total, 'запись', 'записи', 'записей')}{frozen && !capture && ' · пауза'}</span>
                <span className='flex flex-wrap items-center gap-x-4'>
                    {filtered && !capture && <button type='button' onClick={() => update({ device: '', service: '', kind: '', search: '' })} className='flex min-h-10 cursor-pointer items-center gap-1 text-tint'><IconX aria-hidden className='size-4' />Сбросить</button>}
                    {!capture && recentOn && <button type='button' disabled={!active.device} title={active.device ? undefined : 'Сначала выберите устройство'}
                        onClick={() => { setPaused(false); setCapture({ device: active.device, since: new Date().toISOString() }) }}
                        className='flex min-h-10 cursor-pointer items-center gap-1 text-tint disabled:cursor-default disabled:opacity-40'><IconPlayerRecord aria-hidden className='size-4' />Запись</button>}
                    {total > 0 && <button type='button' onClick={exportRows} className='flex min-h-10 cursor-pointer items-center gap-1 text-tint'><IconDownload aria-hidden className='size-4' />Скачать</button>}
                    {!capture?.until && sourceReady && <button type='button' onClick={() => { if (paused && active.source !== 'live') void pages.refetch(); setPaused(!paused) }} className='min-h-10 cursor-pointer text-tint'>{paused ? 'Продолжить' : 'Пауза'}</button>}
                </span>
            </div>
            {incomplete && sourceReady && <div role='status' className='flex flex-wrap items-center justify-between gap-x-4 py-2 text-xs text-warning'>
                <span>Mihomo сообщает не обо всех соединениях — в журнале возможны пропуски.</span>
                {active.source !== 'history' && <button type='button' disabled={enableRecent.isPending} onClick={() => enableRecent.mutate()} className='min-h-10 cursor-pointer text-tint disabled:opacity-50'>Включить полный журнал</button>}
            </div>}
            {!sourceReady ? <div className='py-6 text-sm'>
                <p className='font-medium'>{active.source === 'recent' ? 'Короткий журнал выключен' : 'Журнал на диске выключен'}</p>
                <p className='mt-1 max-w-xl text-muted-foreground'>{active.source === 'recent' ? 'Включите его, чтобы видеть соединения, которые уже закрылись. Записи хранятся в памяти роутера.' : 'Чтобы хранить записи за сутки, выберите внешний диск в настройках журнала.'}</p>
                {active.source === 'recent'
                    ? <button type='button' disabled={enableRecent.isPending} onClick={() => enableRecent.mutate()} className='mt-2 min-h-11 cursor-pointer text-tint disabled:opacity-50'>{enableRecent.isPending ? 'Включаем…' : 'Включить'}</button>
                    : <button type='button' onClick={() => setSettingsOpen(true)} className='mt-2 min-h-11 cursor-pointer text-tint'>Открыть настройки</button>}
                {enableRecent.error && <p role='alert' className='mt-2 text-destructive'>{enableRecent.error.message}</p>}
            </div> : failure ? <Row label='Журнал сейчас недоступен' hint={failure} /> : loading ? <Row label='Читаем журнал…' /> : total === 0
                ? <Row label={filtered || capture ? 'Подходящих записей нет' : 'Записей пока нет'} hint={capture && !capture.until ? 'Пользуйтесь устройством — записи появятся здесь.' : undefined} />
                : active.view === 'sites' ? siteRows.map(site => <SiteRow key={site.host} site={site} service={site.service_id && services.get(site.service_id)}
                    onOpen={() => update({ view: 'list', search: site.host })} />)
                    : rows.map(entry => <LogCard key={entry.id} entry={entry} service={entry.service_id && services.get(entry.service_id)} withDate={active.source === 'history'}
                        onOpen={() => setDetails(entry)}
                        onDevice={capture || !entry.device_id ? undefined : () => update({ device: entry.device_id! })}
                        onService={entry.service_id ? () => update({ service: entry.service_id! }) : undefined} />)}
            {active.view === 'list' && active.source !== 'live' && sourceReady && pages.hasNextPage && <Row label={pages.isFetchingNextPage ? 'Загружаем…' : 'Показать ещё'} tone='tint'
                disabled={pages.isFetchingNextPage} onClick={() => void pages.fetchNextPage()} />}
            {active.view === 'list' && active.source !== 'live' && (pages.data?.pages.length ?? 0) > 1 && !frozen && <Row label='К новым записям' tone='tint'
                onClick={() => { qc.removeQueries({ queryKey: ['journal', filterKey] }); void pages.refetch(); window.scrollTo({ top: 0 }) }} />}
        </Group>

        <LogDetails entry={details} service={details?.service_id && services.get(details.service_id)} onClose={() => setDetails(null)}
            actions={details ? [
                ...(details.host ? [{ label: 'Только этот адрес', onClick: () => { update({ search: details.host }); setDetails(null) } }] : []),
                ...(details.device_id && !capture ? [{ label: 'Только это устройство', onClick: () => { update({ device: details.device_id! }); setDetails(null) } }] : []),
                { label: copied ? 'Скопировано' : 'Скопировать запись', onClick: () => copyEntry(details) },
                ...(details.host && !/^[0-9.]+$|:/.test(details.host) ? [{ label: 'Добавить адрес в исключения', onClick: () => navigate('/exclusions?add=' + encodeURIComponent(details.host)) }] : []),
            ] : undefined} />

        <Sheet open={presetSheet === 'save'} onClose={() => setPresetSheet(null)} title='Новый шаблон'
            done={{ label: savePresets.isPending ? 'Сохраняем…' : 'Сохранить', disabled: savePresets.isPending || !presetName.trim(), onClick: () => savePresets.mutate([...(presets.data ?? []), { id: '', name: presetName.trim(), ...filters }]) }}>
            <Group footer={savePresets.error ? <span role='alert' className='text-destructive'>{savePresets.error.message}</span> : 'Шаблон запомнит период, вид и фильтры. Он появится на всех ваших устройствах.'}>
                <label className='block py-3 text-[15px] font-medium' htmlFor='preset-name'>Название
                    <input id='preset-name' type='text' value={presetName} maxLength={40} autoFocus onChange={event => setPresetName(event.target.value)}
                        placeholder='Например, Claude на компьютере' className={field + ' mt-1.5'} />
                </label>
            </Group>
        </Sheet>
        <Sheet open={presetSheet === 'manage'} onClose={() => setPresetSheet(null)} title='Шаблоны' closeLabel='Готово'>
            <Group footer={savePresets.error ? <span role='alert' className='text-destructive'>{savePresets.error.message}</span> : undefined}>
                {(presets.data ?? []).map(preset => <div key={preset.id} className='flex items-center gap-2 py-2'>
                    <input type='text' aria-label={'Название шаблона ' + preset.name} defaultValue={preset.name} maxLength={40} disabled={savePresets.isPending} className={field}
                        onBlur={event => { const name = event.target.value.trim(); if (name && name !== preset.name) savePresets.mutate((presets.data ?? []).map(item => item.id === preset.id ? { ...item, name } : item)) }} />
                    <button type='button' aria-label={'Удалить шаблон ' + preset.name} disabled={savePresets.isPending}
                        onClick={() => savePresets.mutate((presets.data ?? []).filter(item => item.id !== preset.id))}
                        className='flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-xl text-destructive hover:bg-white/6 disabled:opacity-50'><IconTrash aria-hidden className='size-5' /></button>
                </div>)}
                {(presets.data?.length ?? 0) === 0 && <Row label='Шаблонов пока нет' />}
            </Group>
        </Sheet>
        <TrafficHistorySettings open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </>
}

function SiteRow({ site, service, onOpen }: { site: JournalSite; service?: string; onOpen: () => void }) {
    const parts = [
        site.vpn > 0 && { label: 'VPN ' + count.format(site.vpn), className: 'bg-tint/10 text-tint' },
        site.direct > 0 && { label: 'Напрямую ' + count.format(site.direct), className: 'bg-fill text-muted-foreground' },
        site.blocked > 0 && { label: 'Блокировка ' + count.format(site.blocked), className: 'bg-warning/10 text-warning' },
        site.errors > 0 && { label: 'Ошибки ' + count.format(site.errors), className: 'bg-destructive/10 text-destructive' },
    ].filter(Boolean) as { label: string; className: string }[]
    return <button type='button' onClick={onOpen} title='Показать записи этого адреса' className='flex w-full min-w-0 cursor-pointer items-center gap-3 border-b border-white/10 py-2 text-left last:border-b-0'>
        {site.service_id ? <ServiceLogo id={site.service_id} className='size-5 shrink-0' /> : <IconWorld aria-hidden className='size-5 shrink-0 text-muted-foreground' />}
        <span className='min-w-0 flex-1'>
            <span className='block truncate text-[14px] font-semibold'>{site.host}</span>
            <span className='block truncate text-xs text-muted-foreground'>{[service, site.exit, site.devices > 1 && `устройств: ${site.devices}`, timeLabel(site.last_at)].filter(Boolean).join(' · ')}</span>
            <span className='mt-1 flex flex-wrap gap-1'>{parts.map(part => <span key={part.label} className={'rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-4 ' + part.className}>{part.label}</span>)}</span>
        </span>
        <span className='shrink-0 text-sm tabular-nums text-muted-foreground'>×{count.format(site.count)}</span>
    </button>
}
