import { useMemo, useState } from 'react'
import {
    IconActivityHeartbeat,
    IconCheck,
    IconChevronRight,
    IconLink,
    IconPencil,
    IconPlus,
    IconRefresh,
    IconSearch,
    IconWorldWww,
} from '@tabler/icons-react'
import {
    CircleButton,
    Group,
    IconTile,
    PageTitle,
    Row,
    Segmented,
    Switch,
} from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { ServerSourceForm } from '@/components/serverSourceForm'
import { Badge } from '@/components/ui/badge'
import { AddSiteSheet, SiteSheet, siteSummary } from '@/components/siteSheets'
import {
    usePool,
    useServers,
    useSites,
    useSubscription,
} from '@/hooks/usePanelData'
import { useServerActions } from '@/hooks/useServerActions'
import { useStreamLatency } from '@/hooks/useStreamLatency'
import {
    countryName,
    latencyTone,
    serverCountry,
    timeAgo,
    toneText,
} from '@/lib/format'
import { cn } from '@/lib/utils'
import { importWarnings, safeNotice } from '@/lib/subscription'
import type { Server } from '@/types'

const OTHER = '—'

// One list on a phone, separate cards side by side on a desktop
const TILE = 'lg:rounded-card lg:bg-card lg:px-4'

type CountryGroup = { code: string; list: Server[] }

type Tab = 'pool' | 'all'

const TAB_KEY = 'servers_tab'

function savedTab(): Tab {
    try {
        return localStorage.getItem(TAB_KEY) === 'all' ? 'all' : 'pool'
    } catch {
        return 'pool'
    }
}

export function ServersPage() {
    const servers = useServers().data ?? []
    const pool = usePool().data
    const sites = useSites().data
    const subscription = useSubscription().data
    const {
        select,
        pin,
        auto,
        refreshSubscription,
        setSubscription,
        setCountry,
    } = useServerActions()
    const { check, checking, error: checkError, progress } = useStreamLatency()
    const [query, setQuery] = useState('')
    const [country, setCountryFilter] = useState('all')
    const [sheetOpen, setSheetOpen] = useState(false)
    const [tab, setTabState] = useState<Tab>(savedTab)
    const [addingSite, setAddingSite] = useState(false)
    const [siteId, setSiteId] = useState<number | null>(null)
    const hasSubscription = Boolean(
        subscription?.configured || (subscription?.server_count ?? 0) > 0,
    )
    const warnings = importWarnings(
        subscription?.import_report ??
            setSubscription.data?.import_report ??
            refreshSubscription.data?.import_report,
    )
    const rawActionError =
        select.error?.message ??
        pin.error?.message ??
        auto.error?.message ??
        refreshSubscription.error?.message ??
        refreshSubscription.data?.pool_error
    const actionError = rawActionError
        ? safeNotice(
              rawActionError,
              'Не удалось применить действие. Рабочее подключение сохранено.',
          )
        : ''

    const isPool = pool?.mode === 'pool' && (pool.nodes?.length ?? 0) > 0
    const view: Tab = isPool ? tab : 'all'
    const setTab = (next: Tab) => {
        setTabState(next)
        try {
            localStorage.setItem(TAB_KEY, next)
        } catch {}
    }

    const countries = useMemo(() => {
        const counts = new Map<string, number>()
        servers.forEach(s => {
            const c = serverCountry(s) || OTHER
            counts.set(c, (counts.get(c) ?? 0) + 1)
        })
        return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c)
    }, [servers])

    const groups = useMemo(() => {
        const byCountry = new Map<string, Server[]>()
        servers.forEach(s => {
            const c = serverCountry(s) || OTHER
            if (country !== 'all' && c !== country) return
            if (!matches(query, s.name, c)) return
            byCountry.set(c, [...(byCountry.get(c) ?? []), s])
        })
        const hasActive = (g: CountryGroup) =>
            g.list.some(s => s.active) ? 0 : 1
        return [...byCountry.entries()]
            .map(([code, list]) => ({ code, list: list.sort(byLatency) }))
            .sort(
                (a, b) =>
                    hasActive(a) - hasActive(b) ||
                    (countryName(a.code) || 'я').localeCompare(
                        countryName(b.code) || 'я',
                        'ru',
                    ),
            )
    }, [servers, query, country])

    const poolRows = useMemo(() => {
        const byId = new Map(servers.map(s => [s.id, s]))
        return (pool?.nodes ?? [])
            .map(n => {
                const server = byId.get(n.server_id)
                return {
                    node: n,
                    country: server ? serverCountry(server) : n.country,
                    protocol: server?.protocol,
                    latency: server
                        ? server.probe_kind === 'https'
                            ? server.latency_ms
                            : 0
                        : n.latency_ms,
                    current: n.tag === pool?.current_tag,
                    excluded: !!n.excluded_until,
                }
            })
            .filter(r => matches(query, r.node.name, r.country))
            .sort(
                (a, b) =>
                    Number(b.current) - Number(a.current) ||
                    Number(a.excluded) - Number(b.excluded) ||
                    rank(a.latency) - rank(b.latency),
            )
    }, [pool, servers, query])

    const updated = timeAgo(subscription?.last_updated)
    const rowProps = (s: Server) => ({
        server: s,
        busy: select.isPending,
        onSelect: () => select.mutate(s.id),
        onSetCountry: (c: string) =>
            setCountry.mutate({ id: s.id, country: c }),
    })

    const isAuto = isPool && !pool?.pin_manual
    const pickNode = (tag: string, serverId: number) =>
        serverId >= 0 ? select.mutate(serverId) : pin.mutate(tag)

    const tiles = (
        <div className='divide-y divide-white/10 rounded-card bg-card px-4 lg:grid lg:grid-cols-2 lg:gap-4 lg:divide-y-0 lg:bg-transparent lg:px-0'>
            <div className={TILE}>
                <Row
                    icon={
                        <IconTile color='#6366f1'>
                            <IconLink className='size-[17px]' stroke={2.2} />
                        </IconTile>
                    }
                    label={hasSubscription ? 'Источник серверов' : 'Добавить серверы'}
                    tone={hasSubscription ? undefined : 'tint'}
                    hint={
                        hasSubscription
                            ? `${subscription?.host || 'Ручной источник'}${updated ? ` · обновлена ${updated} назад` : ''}`
                            : 'Подписка, ссылка сервера или файл'
                    }
                    onClick={() => setSheetOpen(true)}
                    trailing={
                        <IconChevronRight
                            className='size-4 shrink-0 text-label-tertiary'
                            stroke={2.6}
                        />
                    }
                />
            </div>
            {hasSubscription && (
                <div className={TILE}>
                    <Row
                        icon={
                            <IconTile color='#30d158'>
                                <IconActivityHeartbeat
                                    className='size-[17px]'
                                    stroke={2.2}
                                />
                            </IconTile>
                        }
                        label={checking ? 'Проверяю HTTPS…' : 'Проверить HTTPS'}
                        hint={
                            checking && progress.total > 0
                                ? progress.completed > 0
                                    ? `Проверено ${progress.completed} из ${progress.total} серверов`
                                    : `Проверка ${progress.total} серверов может занять минуту`
                                : 'Реальное соединение через каждый сервер'
                        }
                        onClick={check}
                        disabled={checking}
                    />
                </div>
            )}
        </div>
    )

    return (
        <>
            <PageTitle
                title='Серверы'
                subtitle={
                    hasSubscription
                        ? `${subscription?.server_count ?? servers.length} серверов${isPool ? ` · ${pool?.nodes?.length} в пуле` : ''}${updated ? ` · обновлено ${updated} назад` : ''}`
                        : 'Добавьте ссылку на подписку'
                }
                action={
                    <div className='flex items-center gap-2'>
                        <SearchField
                            value={query}
                            onChange={setQuery}
                            className='hidden w-64 lg:flex'
                        />
                        {hasSubscription && subscription?.can_refresh !== false && (
                            <CircleButton
                                label='Обновить подписку'
                                onClick={() => refreshSubscription.mutate()}
                                disabled={refreshSubscription.isPending}
                            >
                                <IconRefresh
                                    className={cn(
                                        'size-5',
                                        refreshSubscription.isPending &&
                                            'animate-spin',
                                    )}
                                />
                            </CircleButton>
                        )}
                    </div>
                }
            />

            {warnings.length > 0 && (
                <p
                    role='status'
                    className='px-4 text-[15px] text-muted-foreground'
                >
                    {warnings.join(' ')}
                </p>
            )}
            {checkError && (
                <p role='alert' className='px-4 text-[15px] text-destructive'>
                    {checkError}
                </p>
            )}
            {actionError && (
                <p role='alert' className='px-4 text-[15px] text-destructive'>
                    {actionError}
                </p>
            )}

            {isPool && (
                <div className='lg:max-w-sm'>
                    <Segmented
                        label='Список серверов'
                        value={view}
                        onChange={setTab}
                        options={[
                            {
                                value: 'pool',
                                label: `Пул · ${pool?.nodes?.length ?? 0}`,
                            },
                            { value: 'all', label: `Все · ${servers.length}` },
                        ]}
                    />
                </div>
            )}

            {servers.some(s => s.protocol === 'xray-profile') && (
                <Group title='Режимы провайдера' footer='Профиль применяет свои правила и выбор серверов. Для обычного автовыбора используйте пул панели.'>
                    {servers.filter(s => s.protocol === 'xray-profile').map(server => (
                        <Row key={server.id} label={server.name}
                            hint={server.check_error || `${server.profile_nodes ?? 0} серверов · ${server.active ? 'Выбран' : server.latency_ms > 0 ? `HTTPS ${server.latency_ms} мс` : 'Не прошёл проверку'}`}
                            onClick={() => select.mutate(server.id)}
                            disabled={select.isPending || pin.isPending || auto.isPending || server.active}
                            trailing={server.active ? <IconCheck className='size-5 text-tint' /> : <IconChevronRight className='size-4 text-label-tertiary' />}
                        />
                    ))}
                </Group>
            )}

            {view === 'pool' && (
                <div className='flex flex-col gap-4 lg:grid lg:grid-cols-2 lg:items-start'>
                    <Group
                        title='Пул'
                        footer={
                            isAuto
                                ? 'Панель держит трафик на самом быстром сервере пула и сама переключается, если он перестал работать.'
                                : 'Трафик закреплён за выбранным сервером. Включите автовыбор, чтобы панель снова выбирала сама.'
                        }
                    >
                        <div className='flex min-h-[52px] items-center gap-3 py-2'>
                            <span className='min-w-0 flex-1'>
                                <span className='block text-[17px] tracking-[-0.43px]'>
                                    Выбирать сервер сам
                                </span>
                                {pool?.pin_note && (
                                    <span className='mt-0.5 block text-[13px] text-muted-foreground'>
                                        {pool.pin_note}
                                    </span>
                                )}
                            </span>
                            <Switch
                                checked={isAuto}
                                onChange={next =>
                                    next
                                        ? auto.mutate()
                                        : pool?.current_tag &&
                                          pin.mutate(pool.current_tag)
                                }
                                label='Выбирать сервер сам'
                                disabled={
                                    auto.isPending ||
                                    pin.isPending ||
                                    !pool?.api_available
                                }
                            />
                        </div>
                        {poolRows.map(r => (
                            <PoolRow
                                key={r.node.tag}
                                name={r.node.name}
                                country={r.country}
                                protocol={r.protocol}
                                latency={r.latency}
                                current={r.current}
                                excludedUntil={r.node.excluded_until}
                                busy={select.isPending || pin.isPending}
                                onSelect={() =>
                                    pickNode(r.node.tag, r.node.server_id)
                                }
                            />
                        ))}
                        {poolRows.length === 0 && (
                            <p className='py-4 text-[15px] text-muted-foreground'>
                                Ничего не нашлось
                            </p>
                        )}
                    </Group>

                    <div className='flex flex-col gap-4'>
                        <Group
                            title='Сайты'
                            footer={
                                sites?.unavailable ||
                                'Если сайт открывается не через все серверы пула, добавьте его сюда: панель проверит каждый сервер и пустит сайт только через рабочие.'
                            }
                        >
                            {sites?.sites.map(site => (
                                <Row
                                    key={site.id}
                                    icon={
                                        <IconTile color='#ff9f0a'>
                                            <IconWorldWww
                                                className='size-[17px]'
                                                stroke={2.2}
                                            />
                                        </IconTile>
                                    }
                                    label={siteLabel(site.domains)}
                                    hint={siteSummary(site)}
                                    onClick={() => setSiteId(site.id)}
                                    trailing={
                                        <IconChevronRight
                                            className='size-4 shrink-0 text-label-tertiary'
                                            stroke={2.6}
                                        />
                                    }
                                />
                            ))}
                            <Row
                                icon={
                                    <IconTile color='#0a84ff'>
                                        <IconPlus
                                            className='size-[17px]'
                                            stroke={2.4}
                                        />
                                    </IconTile>
                                }
                                label='Добавить сайт'
                                tone='tint'
                                disabled={!!sites?.unavailable}
                                onClick={() => setAddingSite(true)}
                            />
                        </Group>
                        {tiles}
                    </div>
                </div>
            )}

            {view === 'all' && (
                <>
                    {tiles}

                    {servers.length > 0 && (
                        <div className='flex flex-col gap-3'>
                            <SearchField
                                value={query}
                                onChange={setQuery}
                                className='lg:hidden'
                            />
                            <div
                                role='group'
                                aria-label='Страна'
                                className='-mx-4 flex gap-2 overflow-x-auto px-4 [mask-image:linear-gradient(to_right,transparent,black_16px,black_calc(100%-40px),transparent)] [-webkit-mask-image:linear-gradient(to_right,transparent,black_16px,black_calc(100%-40px),transparent)] [scrollbar-width:none]'
                            >
                                {['all', ...countries].map(c => (
                                    <button
                                        key={c}
                                        type='button'
                                        aria-pressed={c === country}
                                        onClick={() => setCountryFilter(c)}
                                        className={cn(
                                            'min-h-9 shrink-0 cursor-pointer select-none rounded-full px-4 text-[15px] tracking-[-0.24px] transition-colors',
                                            c === country
                                                ? 'bg-white font-semibold text-black'
                                                : 'border border-white/12 bg-white/6 font-medium hover:bg-white/10',
                                        )}
                                    >
                                        {c === 'all'
                                            ? 'Все'
                                            : countryName(c) || 'Без страны'}
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className='flex flex-col gap-4 lg:block lg:columns-2 lg:gap-4'>
                        {groups.map(g => (
                            <Group
                                key={g.code}
                                title={groupTitle(g)}
                                className='lg:mb-4 lg:break-inside-avoid'
                            >
                                {g.list.map(s => (
                                    <ServerRow key={s.id} {...rowProps(s)} />
                                ))}
                            </Group>
                        ))}
                    </div>

                    {servers.length > 0 && groups.length === 0 && (
                        <p className='px-4 text-[15px] text-muted-foreground'>
                            Ничего не нашлось
                        </p>
                    )}
                </>
            )}

            <SubscriptionSheet
                open={sheetOpen}
                onClose={() => setSheetOpen(false)}
                configured={hasSubscription}
                host={subscription?.host}
            />
            <AddSiteSheet
                open={addingSite}
                onClose={() => setAddingSite(false)}
                onCreated={id => {
                    setAddingSite(false)
                    setSiteId(id)
                }}
            />
            <SiteSheet
                site={sites?.sites.find(s => s.id === siteId)}
                onClose={() => setSiteId(null)}
            />
        </>
    )
}

function matches(query: string, name: string, country?: string) {
    const q = query.trim().toLowerCase()
    return (
        !q ||
        name.toLowerCase().includes(q) ||
        countryName(country).toLowerCase().includes(q)
    )
}

function rank(ms: number) {
    return ms > 0 ? ms : Infinity
}

function siteLabel(domains: string[]) {
    return domains.length > 1
        ? `${domains[0]} и ещё ${domains.length - 1}`
        : domains[0]
}

function PoolRow({
    name,
    country,
    protocol,
    latency,
    current,
    excludedUntil,
    busy,
    onSelect,
}: {
    name: string
    country?: string
    protocol?: string
    latency: number
    current: boolean
    excludedUntil?: string
    busy: boolean
    onSelect: () => void
}) {
    const notes = [
        countryName(country),
        excludedUntil &&
            `не отвечал, вернётся в ${new Date(excludedUntil).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })}`,
    ].filter(Boolean)

    return (
        <button
            type='button'
            onClick={onSelect}
            disabled={busy || current}
            className='flex min-h-[52px] w-full cursor-pointer items-center gap-3 py-2 text-left disabled:cursor-default'
        >
            <span className='min-w-0 flex-1'>
                <span
                    className={cn(
                        'block break-words text-[17px] tracking-[-0.43px]',
                        excludedUntil && 'text-muted-foreground',
                    )}
                >
                    {name}
                    {protocol && <ProtocolBadge protocol={protocol} />}
                </span>
                {notes.length > 0 && (
                    <span className='mt-0.5 block text-[13px] text-muted-foreground'>
                        {notes.join(' · ')}
                    </span>
                )}
            </span>
            <span
                className={cn(
                    'shrink-0 text-right text-[15px] tabular-nums',
                    toneText[latencyTone(latency)],
                )}
            >
                {latency === 0 ? '' : latency < 0 ? '—' : `${latency} мс`}
            </span>
            <span className='flex w-6 justify-center'>
                {current && (
                    <IconCheck
                        className='size-[18px] text-tint'
                        stroke={2.8}
                        aria-label='Сейчас используется'
                    />
                )}
            </span>
        </button>
    )
}

function groupTitle(g: CountryGroup) {
    return `${countryName(g.code) || 'Страна не определена'} · ${g.list.length}`
}

function byLatency(a: Server, b: Server) {
    if (a.active !== b.active) return a.active ? -1 : 1
    const la = a.latency_ms < 0 ? Infinity : a.latency_ms || Infinity
    const lb = b.latency_ms < 0 ? Infinity : b.latency_ms || Infinity
    return la - lb
}

function statusOf(server: Server) {
	if (server.check_error) return { label: server.check_error, className: 'text-destructive' }
    if (server.active) return { label: 'Выбран', className: 'text-tint' }
    if (server.probe_kind !== 'https')
        return { label: 'Не проверен', className: 'text-muted-foreground' }
    if (server.latency_ms === -1)
        return { label: 'Не отвечает', className: 'text-destructive' }
    if (server.pool_tag)
        return { label: 'В пуле', className: 'text-muted-foreground' }
    return null
}

function ProtocolBadge({ protocol }: { protocol: string }) {
    const label = ['hysteria', 'hysteria2', 'hy2'].includes(
        protocol.toLowerCase(),
    )
        ? 'Hysteria2'
        : protocol === 'xray-profile' ? 'Профиль' : protocol.toUpperCase()
    return (
        <Badge variant='secondary' className='ml-2 align-middle text-[11px]'>
            {label}
        </Badge>
    )
}

function SearchField({
    value,
    onChange,
    className,
}: {
    value: string
    onChange: (value: string) => void
    className?: string
}) {
    return (
        <label
            className={cn(
                'flex min-h-10 items-center gap-1.5 rounded-xl bg-fill px-2.5',
                className,
            )}
        >
            <IconSearch className='size-4 text-muted-foreground' stroke={2.2} />
            <span className='sr-only'>Поиск</span>
            <input
                type='search'
                value={value}
                onChange={e => onChange(e.target.value)}
                placeholder='Поиск'
                className='min-w-0 flex-1 bg-transparent text-[17px] tracking-[-0.43px] outline-none placeholder:text-muted-foreground'
            />
        </label>
    )
}

function ServerRow({
    server,
    busy,
    onSelect,
    onSetCountry,
}: {
    server: Server
    busy: boolean
    onSelect: () => void
    onSetCountry: (country: string) => void
}) {
    const [editing, setEditing] = useState(false)
    const [value, setValue] = useState(serverCountry(server))
    const status = statusOf(server)
    const measured = server.probe_kind === 'https' ? server.latency_ms : 0
    const ping = measured === 0 ? '' : measured < 0 ? '—' : `${measured} мс`

    if (editing) {
        return (
            <form
                className='flex min-h-12 items-center gap-2 py-2'
                onSubmit={e => {
                    e.preventDefault()
                    onSetCountry(value.trim().toUpperCase())
                    setEditing(false)
                }}
            >
                <span className='min-w-0 flex-1 truncate text-[17px]'>
                    {server.name}
                </span>
                <label className='sr-only' htmlFor={`country-${server.id}`}>
                    Код страны
                </label>
                <input
                    id={`country-${server.id}`}
                    value={value}
                    onChange={e =>
                        setValue(
                            e.target.value
                                .replace(/[^a-zA-Z]/g, '')
                                .slice(0, 2),
                        )
                    }
                    placeholder='NL'
                    autoFocus
                    className='h-9 w-14 rounded-lg bg-fill px-2 text-center text-[15px] uppercase outline-none'
                />
                <button
                    type='submit'
                    className='min-h-9 cursor-pointer px-2 text-[15px] font-semibold text-tint'
                >
                    Готово
                </button>
            </form>
        )
    }

    return (
        <div className='flex items-center gap-1'>
            <button
                type='button'
                onClick={onSelect}
                disabled={busy || server.active}
                className='flex min-h-[52px] min-w-0 flex-1 cursor-pointer items-center gap-3 py-2 text-left disabled:cursor-default'
            >
                <span className='min-w-0 flex-1'>
                    <span className='block break-words text-[17px] tracking-[-0.43px]'>
                        {server.name}
                        <ProtocolBadge protocol={server.protocol} />
                    </span>
                    {status && (
                        <span
                            className={cn(
                                'mt-0.5 block text-[13px]',
                                status.className,
                            )}
                        >
                            {status.label}
                        </span>
                    )}
                </span>
                <span
                    className={cn(
                        'shrink-0 text-right text-[15px] tabular-nums',
                        toneText[latencyTone(measured)],
                    )}
                >
                    {ping}
                </span>
                <span className='flex w-6 justify-center'>
                    {server.active && (
                        <IconCheck
                            className='size-[18px] text-tint'
                            stroke={2.8}
                            aria-label='Выбран'
                        />
                    )}
                </span>
            </button>
            <button
                type='button'
                aria-label={`Изменить страну для ${server.name}`}
                onClick={() => {
                    setValue(serverCountry(server))
                    setEditing(true)
                }}
                className='flex size-10 shrink-0 cursor-pointer items-center justify-center rounded-full text-label-tertiary hover:text-muted-foreground'
            >
                <IconPencil className='size-4' />
            </button>
        </div>
    )
}

function SubscriptionSheet({ open, onClose, configured, host }: {
    open: boolean
    onClose: () => void
    configured?: boolean
    host?: string
}) {
    return <Sheet open={open} onClose={onClose} title='Источник серверов'>
        <Group footer='Подойдёт подписка провайдера, готовая ссылка собственного сервера или файл. Панель проверит настоящее HTTPS-соединение перед применением.'>
            {open && <ServerSourceForm onApplied={() => onClose()} />}
        </Group>
        {configured && <Group title='Сейчас'><Row label={host || 'Серверы сохранены локально'} hint='Чтобы заменить источник, импортируйте новый выше.' /></Group>}
    </Sheet>
}
