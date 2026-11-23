import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
    IconAlertTriangle,
    IconBan,
    IconCheck,
    IconChevronLeft,
    IconChevronRight,
    IconClockPause,
    IconCloudDownload,
    IconGauge,
    IconLink,
    IconLayersLinked,
    IconPlus,
    IconSearch,
    IconWand,
    IconWorld,
    IconWorldWww,
} from '@tabler/icons-react'
import { Hint } from '@/components/hint'
import { LatencySkeleton, SignalBars } from '@/components/probeIndicators'
import { ExcludedLocations } from '@/components/serverAutomation'
import {
    CircleButton,
    Group,
    IconTile,
    PageTitle,
    Row,
    Segmented,
    Switch,
} from '@/components/ios'
import { MultiPoolsSheet, SourcesSheet } from '@/components/serverCatalogSheets'
import { Badge } from '@/components/ui/badge'
import { AddSiteSheet, SiteSheet, siteSummary } from '@/components/siteSheets'
import {
    useMultiPools,
    usePanelSettings,
    usePool,
    useServers,
    useServerSources,
    useSites,
    useStatus,
    useSubscription,
} from '@/hooks/usePanelData'
import { useServerActions } from '@/hooks/useServerActions'
import { useStreamLatency } from '@/hooks/useStreamLatency'
import {
    agoLabel,
    countryName,
    countryLabel,
    isSet,
    latencyTone,
    locationExcluded,
    scopeLabel,
    serverCountry,
    timeAgo,
    toneText,
    unavailableCountryReason,
    withCountryFlag,
} from '@/lib/format'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { importWarnings, safeNotice } from '@/lib/subscription'
import type { AutoScope, PoolNode, Server } from '@/types'

const OTHER = '—'

// One list on a phone, separate cards side by side on a desktop
const TILE = 'lg:rounded-card lg:bg-card lg:px-4'

type CountryGroup = { code: string; list: Server[]; bestLatency: number }
type CountryOrder = 'name-asc' | 'name-desc' | 'latency'

type Tab = 'pool' | 'all'

// How the owner left the screen. It is kept on the router, so every device
// and every new sign-in opens the screen the same way.
type ServersView = { tab: Tab; country_order: CountryOrder; country: string; only_responding: boolean }
const defaultView: ServersView = { tab: 'pool', country_order: 'name-asc', country: 'all', only_responding: false }
const viewKey = ['ui-servers']

function useServersView() {
    const qc = useQueryClient()
    const query = useQuery({ queryKey: viewKey, queryFn: () => api.get<ServersView>('/api/ui/servers'), staleTime: Infinity })
    const save = useMutation({
        mutationFn: (view: ServersView) => api.put<ServersView>('/api/ui/servers', view),
        onMutate: view => { qc.setQueryData(viewKey, view) },
    })
    return {
        view: query.data ?? defaultView,
        change: (next: Partial<ServersView>) => save.mutate({ ...(qc.getQueryData<ServersView>(viewKey) ?? defaultView), ...next }),
    }
}

// A provider's note under a server name, cut to fit one line.
function shortNote(text?: string) {
    if (!text) return ''
    return text.length > 30 ? text.slice(0, 29).trimEnd() + '…' : text
}
// The import notice the owner has already read and closed.
const NOTICE_KEY = 'xkeen.servers.notice.v1'

function savedNotice() {
    try {
        return localStorage.getItem(NOTICE_KEY) ?? ''
    } catch {
        return ''
    }
}
const countryCollator = new Intl.Collator('ru', { sensitivity: 'base' })

function countryPoolOption(scope: AutoScope, avoided: string[]) {
    const name = scopeLabel(scope)
    if (scope.country && avoided.includes(scope.country)) {
        return <option key={scope.id} value={scope.id} disabled>{name} · страна исключена</option>
    }
    const total = scope.catalog_count ?? scope.member_count
    if (scope.member_count > 0) {
        const count = scope.member_count === total ? total : `${scope.member_count} из ${total}`
        return <option key={scope.id} value={scope.id}>{name} · {count}</option>
    }
    return <option key={scope.id} value={scope.id} disabled>{name}{total > 0 && ` · ${total} в подписках`} · {unavailableCountryReason(scope, avoided)}</option>
}

function countryOrder(value: string | null): CountryOrder {
    return value === 'name-desc' || value === 'latency' ? value : 'name-asc'
}

export function ServersPage() {
    const servers = useServers().data ?? []
    const poolQuery = usePool()
    const pool = poolQuery.data
    const sources = useServerSources().data
    const status = useStatus().data
    const mihomo = status?.core === 'mihomo' || pool?.core === 'mihomo'
    const poolCatalog = useMultiPools(mihomo)
    const multipools = poolCatalog.data?.pools ?? []
    const scopes = poolCatalog.data?.scopes ?? []
    const avoidCountries = usePanelSettings().data?.avoid_countries ?? []
    const isPool = pool?.mode === 'pool'
    const isAuto = pool?.selection_kind ? pool.selection_kind === 'auto' : isPool && !pool?.pin_manual
    const selectedScope = scopes.find(item => item.id === pool?.auto_scope_id)
    const allLocations = scopes.find(item => item.kind === 'all')
    const countries = scopes.filter(scope => scope.kind === 'country' && !avoidCountries.includes(scope.country ?? ''))
        .sort((a, b) => countryCollator.compare(countryName(a.country), countryName(b.country)))
    const availableCountries = countries.filter(scope => scope.member_count > 0)
    const unavailableCountries = countries.filter(scope => !scope.member_count
        && (scope.unavailable_reason !== 'no_servers' || scope.id === selectedScope?.id))
    if (isAuto && selectedScope?.kind === 'country' && avoidCountries.includes(selectedScope.country ?? '')) {
        unavailableCountries.push(selectedScope)
    }
    const customScopes = scopes.filter(scope => scope.kind === 'custom')
    const sourceScopes = scopes.filter(scope => scope.kind === 'source')
    const shownScope = isAuto ? selectedScope ?? allLocations : undefined
    // Only «Все локации» has a limit of its own; other pools take every server they hold.
    const wholePool = shownScope && (shownScope.kind === 'source' || shownScope.kind === 'custom') ? shownScope : undefined
    const routerMeasured = (pool?.nodes ?? []).some(node => node.router_latency_ms !== undefined)
    const providerModes = servers.filter(s => s.protocol === 'xray-profile')
    const sites = useSites().data
    const subscription = useSubscription().data
    const {
        select,
        pin,
        auto,
        refreshSubscription,
        setScope,
        setPoolLimit,
    } = useServerActions()
    const routeBusy = select.isPending || pin.isPending || auto.isPending || setScope.isPending || setPoolLimit.isPending
    const { check, stop, stopping, stopped, background, checking, error: checkError, progress, isPendingServer, latencyFor } = useStreamLatency()
    const [query, setQuery] = useState('')
    const { view: saved, change: changeView } = useServersView()
    const order = saved.country_order
    const onlyResponding = saved.only_responding
    const [params, setParams] = useSearchParams()
    // Settings link here with ?sources=1 to open the list of subscriptions.
    const [catalogSheet, setCatalogSheet] = useState<'sources' | 'pools' | null>(() => params.get('sources') === '1' ? 'sources' : null)
    const closeCatalog = () => {
        setCatalogSheet(null)
        if (params.has('sources')) setParams({}, { replace: true })
    }
    const [hiddenNotice, setHiddenNotice] = useState(savedNotice)
    const [editingPool, setEditingPool] = useState<string | null>(null)
    const [addingSite, setAddingSite] = useState(false)
    const [siteId, setSiteId] = useState<number | null>(null)
    const hasSubscription = Boolean(
        subscription?.configured || (subscription?.server_count ?? 0) > 0,
    )
    const warnings = importWarnings(
        subscription?.import_report ??
            refreshSubscription.data?.import_report,
    )
    const rawActionError =
        setScope.error?.message ?? poolCatalog.error?.message ??
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

    const canChoosePool = isPool || (mihomo && scopes.length > 0)
    const view: Tab = canChoosePool ? saved.tab : 'all'
    const setTab = (next: Tab) => changeView({ tab: next })

    const routerNodes = useMemo(() => new Map((pool?.nodes ?? [])
        .filter(node => node.server_id >= 0 && node.router_latency_ms !== undefined)
        .map(node => [node.server_id, node])), [pool])
    const routerLatency = useMemo(() => new Map([...routerNodes].map(([id, node]) => [id, node.router_latency_ms!])), [routerNodes])
    // The number a row shows: the router's own for pool servers, a running
    // check's, or the last completed check.
    const shownLatency = (s: Server) => routerLatency.get(s.id) ?? latencyFor(s.id)
        ?? (s.probe_kind === 'https' && !s.check_error ? s.latency_ms : 0)

    const catalogGroups = useMemo(() => groupServers(servers, order), [servers, order])
    // «Только ответившие» hides servers without an answer, and countries left empty.
    const shownGroups = onlyResponding
        ? catalogGroups.map(g => ({ ...g, list: g.list.filter(s => shownLatency(s) > 0) })).filter(g => g.list.length > 0)
        : catalogGroups
    const country = saved.country === 'all' || catalogGroups.some(g => g.code === saved.country) ? saved.country : 'all'
    const countryEmpty = country !== 'all' && !shownGroups.some(g => g.code === country)
    const groups = shownGroups
        .filter(g => country === 'all' || g.code === country)
        .map(g => ({ ...g, list: g.list.filter(s => matches(query, s.name, g.code, s.source_name, s.description)) }))
        .filter(g => g.list.length > 0)

    const poolRows = useMemo(() => {
        const byId = new Map(servers.map(s => [s.id, s]))
        return (pool?.nodes ?? [])
            .map(n => {
                const server = byId.get(n.server_id)
                return {
                    node: n,
                    server,
                    country: server ? serverCountry(server) : n.country,
                    protocol: server?.protocol,
                    source: server?.source_name,
                    description: server?.description,
                    // The router picks by its own measurement, so that is the number to show.
                    routerMeasured: n.router_latency_ms !== undefined,
                    latency: n.router_latency_ms ?? (server
                        ? server.probe_kind === 'https'
                            ? server.latency_ms
                            : 0
                        : n.latency_ms),
                    current: n.tag === pool?.current_tag,
                    excluded: !!n.excluded_until,
                }
            })
            .filter(r => matches(query, r.node.name, r.country, r.source, r.description))
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
        countryExcluded: locationExcluded(avoidCountries, serverCountry(s)),
        busy: routeBusy,
        probeBusy: checking || routeBusy,
        measuring: isPendingServer(s.id),
        // A pool server shows the router's own number in every list.
        routerNode: routerNodes.get(s.id),
        liveLatency: latencyFor(s.id),
        onCheck: () => check([s.id]),
        onSelect: () => select.mutate(s.id),
    })

    const pickNode = (tag: string, serverId: number) =>
        serverId >= 0 ? select.mutate(serverId) : pin.mutate(tag)

    const probing = checking && !background
    // Beside the pool list the column is narrow, so the blocks stack there.
    const tiles = (narrow: boolean) => (
        <div className={cn('flex flex-col gap-3 lg:gap-4', !narrow && 'lg:grid lg:grid-cols-2')}>
        <div className='divide-y divide-white/10 rounded-card bg-card px-4 lg:contents lg:divide-y-0'>
            <div className={TILE}>
                <Row
                    icon={
                        <IconTile color='#6366f1'>
                            <IconLink className='size-[17px]' stroke={2.2} />
                        </IconTile>
                    }
                    label='Подписки и источники'
                    tone={hasSubscription ? undefined : 'tint'}
                    hint={
                        sources?.length
                            ? sources.length === 1 ? sources[0].name : 'Источников: ' + sources.length
                            : 'Добавить подписку, ссылку сервера или файл'
                    }
                    onClick={() => setCatalogSheet('sources')}
                    trailing={
                        <IconChevronRight
                            className='size-4 shrink-0 text-label-tertiary'
                            stroke={2.6}
                        />
                    }
                />
            </div>
            {mihomo && <div className={TILE}>
                <Row icon={<IconTile color='#5856d6'><IconLayersLinked className='size-[17px]' stroke={2.2} /></IconTile>}
                    label='Мультипулы' hint={multipools?.length ? 'Пулов: ' + multipools.length : 'Объединить серверы из разных подписок'}
                    onClick={() => { setEditingPool(null); setCatalogSheet('pools') }} trailing={<IconChevronRight className='size-4 shrink-0 text-label-tertiary' />} />
            </div>}
            <div className={TILE}>
                <ExcludedLocations />
            </div>
        </div>
            {hasSubscription && (
                // Its own card with a brighter edge; stripes drift over it while a check runs.
                <div className={cn('rounded-card bg-card px-4 ring-1 ring-[#30d158]/70', probing && 'probe-running')}>
                    <Row
                        icon={
                            <IconTile color='#30d158'>
                                <IconGauge
                                    className='size-[17px]'
                                    stroke={2.2}
                                />
                            </IconTile>
                        }
                        label={probing ? (stopping ? 'Останавливаю…' : 'Остановить проверку') : 'Проверить пинг'}
                        hint={
                            background
                                ? 'Панель сейчас проверяет серверы пула. Нажмите, чтобы проверить все.'
                                : checking && progress.total > 0
                                ? `Проверено ${progress.completed} из ${progress.total}. Нажмите ещё раз, чтобы остановить.`
                                : stopped
                                ? 'Проверка остановлена. Уже измеренные серверы сохранены.'
                                : 'Все серверы разом, затем загрузка через ответившие'
                        }
                        onClick={() => (probing ? stop() : check())}
                        disabled={stopping}
                    />
                </div>
            )}
        </div>
    )

    const automationLink = (
        <Group>
            <Row icon={<IconTile color='#ff9f0a'><IconCloudDownload className='size-[17px]' stroke={2.2} /></IconTile>}
                label='Подписки и автоматика' hint='Как часто обновлять подписки, когда менять сервер, какие страны не брать'
                to='/settings/automation' />
        </Group>
    )

    const profiles = providerModes.filter(s => matches(query, s.name, serverCountry(s), s.source_name))
    const providerCard = profiles.length > 0 && (
        <Group title={<span className='flex min-w-0 items-center justify-between gap-2'>
            <span>Режимы провайдера</span>
            <ProbeButton label='Обновить пинг режимов провайдера' disabled={checking || routeBusy}
                measuring={providerModes.every(server => isPendingServer(server.id))}
                onClick={() => check(providerModes.map(server => server.id))} />
        </span>} footer='Это готовые варианты из вашей подписки. Какие серверы входят в каждый вариант и как они выбираются, решает поставщик VPN.'>
            {profiles.map(server => <ServerCard key={server.id}
                title={withCountryFlag(server.name, serverCountry(server))}
                chips={<>
                    <ProtocolBadge protocol={server.protocol} className='' />
                    {server.active && <Hint label='Выбран: через этот режим идут остальные сайты' className='text-tint'>
                        <IconCheck aria-hidden className='size-[13px]' stroke={3} />
                    </Hint>}
                </>}
                source={[server.source_name, `${server.profile_nodes ?? 0} серверов`].filter(Boolean).join(' · ')}
                check={checkInfo(server, undefined, latencyFor(server.id))}
                measuring={isPendingServer(server.id)}
                highlighted={server.active}
                selectLabel={`Выбрать режим ${server.name}`}
                onSelect={() => select.mutate(server.id)}
                selectDisabled={routeBusy || server.active}
                probe={{ label: `Обновить пинг сервера ${server.name}`, disabled: checking || routeBusy, onCheck: () => check([server.id]) }}
            />)}
        </Group>
    )

    return (
        <>
            <PageTitle
                title='Серверы'
                subtitle={
                    hasSubscription
                        ? `Серверов: ${subscription?.server_count ?? servers.length}${isPool ? ` · В автовыборе ${pool?.nodes?.length ?? 0}` : ''}${updated ? ` · обновлено ${updated}${updated === 'только что' ? '' : ' назад'}` : ''}`
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
                                label='Обновить все подписки'
                                onClick={() => refreshSubscription.mutate()}
                                disabled={refreshSubscription.isPending}
                            >
                                <IconCloudDownload
                                    className={cn(
                                        'size-5',
                                        refreshSubscription.isPending &&
                                            'motion-safe:animate-pulse',
                                    )}
                                />
                            </CircleButton>
                        )}
                    </div>
                }
            />

            {warnings.length > 0 && warnings.join(' ') !== hiddenNotice && (
                <div role='status' className='flex items-start gap-3 px-4 text-[15px] text-muted-foreground'>
                    <p className='min-w-0 flex-1'>{warnings.join(' ')}</p>
                    <button type='button' className='shrink-0 cursor-pointer text-tint' onClick={() => {
                        const text = warnings.join(' ')
                        setHiddenNotice(text)
                        try { localStorage.setItem(NOTICE_KEY, text) } catch { /* hidden until reload */ }
                    }}>Скрыть</button>
                </div>
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

            {canChoosePool && (
                <div className='lg:max-w-sm'>
                    <Segmented
                        label='Список серверов'
                        value={view}
                        onChange={setTab}
                        options={[
                            {
                                value: 'pool',
                                label: `Автовыбор · ${pool?.nodes?.length ?? 0}`,
                                icon: <IconWand aria-hidden className='size-[17px] shrink-0' stroke={2} />,
                            },
                            {
                                value: 'all',
                                label: `Все серверы · ${servers.length}`,
                                icon: <IconWorld aria-hidden className='size-[17px] shrink-0' stroke={2} />,
                            },
                        ]}
                    />
                </div>
            )}

            {view === 'pool' && (
                <div className='flex flex-col gap-4 lg:grid lg:grid-cols-2 lg:items-start'>
                    <div className='flex min-w-0 flex-col gap-4'>
                        <Group
                            title='Автовыбор'
                            footer={
                                isAuto
                                    ? 'Роутер сам регулярно проверяет серверы пула и ведёт трафик через самый быстрый. Если сервер перестал отвечать, роутер переходит на другой, а панель заменяет его в пуле.'
                                        + (routerMeasured ? ' Числа в этом списке — замеры самого роутера.' : '')
                                    : mihomo ? 'Выбор пула включит автоматический режим.' : 'Включите автовыбор, чтобы панель снова выбирала сервер сама.'
                            }
                        >
                            <div className='flex min-h-[52px] items-center gap-3 py-2'>
                                <span className='min-w-0 flex-1'>
                                    <span className='block text-[17px] tracking-[-0.43px]'>
                                        Автоматически выбирать сервер
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
                                    label='Автоматически выбирать сервер'
                                    disabled={
                                        routeBusy ||
                                        (!isAuto && !pool?.api_available) || (isAuto && !pool?.current_tag)
                                    }
                                />
                            </div>
                            {mihomo && scopes.length > 0 && <div className='py-2'>
                              <div className='flex flex-wrap items-center justify-between gap-x-3 gap-y-1'>
                                <label htmlFor='auto-pool-scope' className='text-[15px] font-medium'>Пул автовыбора</label>
                                <select id='auto-pool-scope' aria-describedby='auto-pool-scope-hint' className='min-h-10 min-w-0 max-w-full flex-1 rounded-xl border border-white/10 bg-fill px-2 text-[15px] sm:max-w-72'
                                    value={setScope.isPending ? setScope.variables : isAuto ? (selectedScope?.id ?? allLocations?.id ?? '') : ''}
                                    disabled={routeBusy || !pool?.api_available}
                                    onChange={e => setScope.mutate(e.target.value)}>
                                    {!isAuto && <option value='' disabled>Выберите пул…</option>}
                                    {allLocations && <option value={allLocations.id} disabled={!allLocations.member_count}>{scopeLabel(allLocations)}</option>}
                                    {customScopes.length > 0 && <optgroup label='Мои пулы'>
                                        {customScopes.map(item => <option key={item.id} value={item.id} disabled={!item.member_count}>{scopeLabel(item)} · {item.member_count || 'нет подходящих серверов'}</option>)}
                                    </optgroup>}
                                    {sourceScopes.length > 0 && <optgroup label='Пулы подписок'>
                                        {sourceScopes.map(item => <option key={item.id} value={item.id} disabled={!item.member_count}>{scopeLabel(item)} · {item.member_count || 'нет подходящих серверов'}</option>)}
                                    </optgroup>}
                                    {availableCountries.length > 0 && <optgroup label='Пулы стран'>{availableCountries.map(item => countryPoolOption(item, avoidCountries))}</optgroup>}
                                    {unavailableCountries.length > 0 && <optgroup label='Недоступные страны'>{unavailableCountries.map(item => countryPoolOption(item, avoidCountries))}</optgroup>}
                                </select>
                              </div>
                              <p id='auto-pool-scope-hint' className='mt-1 text-[13px] text-muted-foreground'>
                                  {shownScope?.kind === 'source' ? 'Роутер выбирает самый быстрый сервер только из этой подписки.'
                                      : shownScope?.kind === 'custom' ? 'Роутер выбирает самый быстрый сервер из вашего пула.'
                                      : shownScope?.kind === 'country' ? 'Роутер выбирает самый быстрый сервер среди тех, которые в подписках помечены этой страной.'
                                      : 'Роутер выбирает самый быстрый сервер из всех подписок. Можно выбрать пул одной подписки, свой пул или страну.'}
                              </p>
                            </div>}
                            {mihomo && wholePool && (
                                <div className='flex flex-wrap items-center justify-between gap-2 py-3'>
                                    <div className='min-w-0 flex-1'>
                                        <p className='text-[15px] font-medium'>Лимит пула «{scopeLabel(wholePool)}»</p>
                                        <p className='text-[13px] text-muted-foreground'>
                                            Берутся все серверы этого пула. Лимит пула «Все локации»{allLocations?.limit ? ` (${allLocations.limit})` : ''} сохранён и вернётся вместе с ним.
                                        </p>
                                    </div>
                                    <input type='number' readOnly disabled aria-label='Серверов в пуле' value={wholePool.member_count}
                                        className='min-h-10 w-[5rem] rounded-xl border border-white/10 bg-fill px-2 text-center text-[16px] text-foreground tabular-nums opacity-60' />
                                </div>
                            )}
                            {mihomo && allLocations?.limit != null && allLocations.eligible_count != null
                                && (!isAuto || (selectedScope ?? allLocations).kind === 'all') && (
                                <AllLocationsLimit
                                    limit={allLocations.limit} count={allLocations.member_count}
                                    eligible={allLocations.eligible_count} disabled={routeBusy || !pool?.api_available}
                                    mutation={setPoolLimit}
                                />
                            )}
                            {poolRows.map(r => (
                                <PoolRow
                                    key={r.node.tag}
                                    node={r.node}
                                    country={r.country}
                                    protocol={r.protocol}
                                    source={r.source}
                                    description={r.description}
                                    server={r.server}
                                    liveLatency={latencyFor(r.node.server_id)}
                                    // The panel checks pool servers too; while it does, the row shows it
                                    // like any other, and the router's number returns afterwards.
                                    measuring={r.node.server_id >= 0 && isPendingServer(r.node.server_id)}
                                    current={r.current}
                                    countryExcluded={locationExcluded(avoidCountries, r.country)}
                                    busy={routeBusy}
                                    probeBusy={checking || routeBusy}
                                    onCheck={r.node.server_id >= 0 ? () => check([r.node.server_id]) : undefined}
                                    onSelect={() =>
                                        pickNode(r.node.tag, r.node.server_id)
                                    }
                                />
                            ))}
                            {poolRows.length === 0 && (
                                <p className='py-4 text-[15px] text-muted-foreground'>
                                    {query ? 'Ничего не нашлось' : 'Доступных серверов для автовыбора нет'}
                                </p>
                            )}
                        </Group>
                    {providerCard}
                    </div>

                    <div className='flex flex-col gap-4'>
                        {automationLink}
                        {!mihomo && <Group
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
                        </Group>}
                        {tiles(true)}
                    </div>
                </div>
            )}

            {view === 'all' && (
                <>
                    {tiles(false)}

                    {servers.length > 0 && (
                        <div className='flex min-w-0 max-w-full flex-col gap-3'>
                            <SearchField
                                value={query}
                                onChange={setQuery}
                                className='lg:hidden'
                            />
                            <div className='flex flex-wrap items-center gap-x-5 gap-y-2 text-[15px]'>
                                <label className='flex flex-wrap items-center gap-x-3 gap-y-1'>
                                    <span>Порядок стран</span>
                                    <select value={order}
                                        className='min-h-10 max-w-full rounded-xl border border-white/10 bg-fill px-2'
                                        onChange={event => changeView({ country_order: countryOrder(event.target.value) })}>
                                        <option value='name-asc'>По названию (А–Я)</option>
                                        <option value='name-desc'>По названию (Я–А)</option>
                                        <option value='latency'>По наименьшему пингу</option>
                                    </select>
                                </label>
                                <label className='flex min-h-10 cursor-pointer items-center gap-2'>
                                    <input type='checkbox' className='size-5 shrink-0 accent-[var(--primary)]' checked={onlyResponding}
                                        onChange={event => changeView({ only_responding: event.target.checked })} />
                                    Только ответившие
                                </label>
                            </div>
                            <CountryFilter groups={shownGroups} value={country} onChange={code => changeView({ country: code })} />
                        </div>
                    )}

                    {countryEmpty && (
                        <p className='px-4 text-[15px] text-muted-foreground'>
                            В этой стране сейчас нет ответивших серверов
                        </p>
                    )}

                    <CountryCatalog groups={groups} rowProps={rowProps}
                        probeBusy={checking || routeBusy}
                        isPendingGroup={code => catalogGroups.find(group => group.code === code)?.list.every(server => isPendingServer(server.id)) ?? false}
                        onCheckGroup={code => check(catalogGroups.find(group => group.code === code)?.list.map(server => server.id) ?? [])} />

                    {mihomo && multipools.some(item => matches(query, item.name)) && (
                        <Group title='Мультипулы'>
                            {multipools.filter(item => matches(query, item.name)).map(item => <Row key={item.id} label={item.name}
                                hint={`${item.member_count} серверов${pool?.auto_scope_id === item.id && isAuto ? ' · Для остальных сайтов' : ''}`}
                                onClick={() => { setEditingPool(item.id); setCatalogSheet('pools') }}
                                trailing={<IconChevronRight className='size-4 text-label-tertiary' />} />)}
                        </Group>
                    )}
                    {servers.length > 0 && groups.length === 0 && !countryEmpty && !profiles.length && !multipools.some(item => matches(query, item.name)) && (
                        <p className='px-4 text-[15px] text-muted-foreground'>
                            Ничего не нашлось
                        </p>
                    )}
                    {/* The list comes first; what is rarely touched follows it. */}
                    {providerCard}
                    {automationLink}
                </>
            )}

            <SourcesSheet open={catalogSheet === 'sources'} onClose={closeCatalog} />
            <MultiPoolsSheet initialId={editingPool} open={catalogSheet === 'pools'} onClose={closeCatalog} />
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

function AllLocationsLimit({ limit, count, eligible, disabled, mutation }: {
    limit: number
    count: number
    eligible: number
    disabled: boolean
    mutation: ReturnType<typeof useServerActions>['setPoolLimit']
}) {
    const [draft, setDraft] = useState<string | null>(null)
    const value = draft ?? String(limit)
    const number = Number(value)
    const valid = /^\d+$/.test(value) && number >= 1 && number <= 256
    const canSave = valid && number !== limit && !disabled
    return (
        <form className='space-y-1.5 py-3' onSubmit={event => {
            event.preventDefault()
            if (canSave) mutation.mutate(number, { onSuccess: () => setDraft(null) })
        }}>
            <div className='flex flex-wrap items-center justify-between gap-2'>
                <div>
                    <label htmlFor='all-locations-limit' className='text-[15px] font-medium'>Лимит пула «Все локации»</label>
                    <p className='text-[13px] text-muted-foreground'>От 1 до 256 серверов</p>
                </div>
                <div className='flex items-center gap-2'>
                    <input id='all-locations-limit' type='number' inputMode='numeric' min={1} max={256} step={1}
                        className='min-h-10 w-[5rem] rounded-xl border border-white/10 bg-fill px-2 text-center text-[16px] text-foreground tabular-nums'
                        value={value} disabled={disabled} aria-invalid={!valid}
                        aria-describedby='all-locations-summary all-locations-feedback'
                        onChange={event => { setDraft(event.target.value); mutation.reset() }} />
                    <button type='submit' disabled={!canSave}
                        className='min-h-10 rounded-xl bg-fill px-3 text-[15px] font-medium text-tint disabled:opacity-50'>
                        {mutation.isPending ? 'Сохраняю…' : 'Сохранить'}
                    </button>
                </div>
            </div>
            <p id='all-locations-summary' className='text-[13px] text-muted-foreground'>
                В пуле {count} из {eligible} подходящих. Первыми попадают серверы с наименьшей задержкой из всех подписок.
                {' '}Дубли, исключённые страны, сборные профили и узлы с неудачной HTTPS-проверкой пропускаются.
            </p>
            <div id='all-locations-feedback' aria-live='polite' className='text-[13px] empty:hidden'>
                {!valid ? 'Введите целое число от 1 до 256.' : mutation.isError
                    ? safeNotice(mutation.error.message, 'Не удалось сохранить лимит.')
                    : mutation.isSuccess ? 'Лимит сохранён.' : ''}
            </div>
        </form>
    )
}

function matches(query: string, name: string, country?: string, source?: string, description?: string) {
    const q = query.trim().toLowerCase()
    return (
        !q ||
        name.toLowerCase().includes(q) ||
        !!source?.toLowerCase().includes(q) ||
        !!description?.toLowerCase().includes(q) ||
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
    node,
    server,
    country,
    protocol,
    source,
    description,
    liveLatency,
    measuring,
    current,
    countryExcluded,
    busy,
    probeBusy,
    onCheck,
    onSelect,
}: {
    node: PoolNode
    server?: Server
    country?: string
    protocol?: string
    source?: string
    description?: string
    liveLatency?: number
    measuring: boolean
    current: boolean
    countryExcluded: boolean
    busy: boolean
    probeBusy: boolean
    onCheck?: () => void
    onSelect: () => void
}) {
    const excludedUntil = node.excluded_until
    const back = excludedUntil && new Date(excludedUntil).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    return (
        <ServerCard
            title={withCountryFlag(node.name, country)}
            titleMuted={!!excludedUntil}
            chips={<>
                {protocol && <ProtocolBadge protocol={protocol} className='' />}
                {excludedUntil && <Hint label={`Не отвечал роутеру. Вернётся в пул в ${back}`} className='text-warning'>
                    <IconClockPause aria-hidden className='size-[13px]' stroke={2.2} />
                </Hint>}
                {countryExcluded && <Hint label='Локация исключена из автовыбора'>
                    <IconBan aria-hidden className='size-[13px]' stroke={2.2} />
                </Hint>}
                {current && <Hint label='Сейчас роутер ведёт трафик через этот сервер' className='text-tint'>
                    <IconCheck aria-hidden className='size-[13px]' stroke={3} />
                </Hint>}
            </>}
            source={source}
            note={shortNote(description) || undefined}
            noteTitle={description}
            check={checkInfo(server, node, liveLatency)}
            measuring={measuring}
            highlighted={current}
            selectLabel={`Выбрать сервер ${node.name}`}
            onSelect={onSelect}
            selectDisabled={busy || current}
            probe={onCheck && { label: `Обновить пинг сервера ${node.name}`, disabled: probeBusy, onCheck }}
        />
    )
}

// While a server is measured its old number gives way to a grey bar until
// the new one arrives.
function Latency({ measuring, ms }: { measuring: boolean; ms: number }) {
    return <span aria-busy={measuring || undefined}
        className={cn('inline-flex w-[4.25rem] shrink-0 justify-end text-[15px] tabular-nums', toneText[latencyTone(ms)])}>
        {measuring ? <LatencySkeleton />
            : ms > 0 ? `${ms} мс`
            : ms < 0 ? <span aria-label='Нет ответа' title='Нет ответа'>—</span>
            : <span className='text-muted-foreground' aria-label='Не проверен' title='Не проверен'>—</span>}
    </span>
}

// While its servers are measured the gauge gives way to signal bars; they stay
// on the button until the check ends.
function ProbeButton({ label, disabled, measuring, onClick }: {
    label: string
    disabled: boolean
    measuring: boolean
    onClick: () => void
}) {
    return <button type='button' aria-label={label} title={label} aria-busy={measuring}
        disabled={disabled} onClick={onClick}
        className={cn('pointer-events-auto relative z-10 flex size-10 shrink-0 cursor-pointer items-center justify-center rounded-full text-tint hover:bg-white/8 focus-visible:outline-2 focus-visible:outline-tint disabled:cursor-default',
            !measuring && 'disabled:opacity-45')}>
        {measuring ? <SignalBars /> : <IconGauge aria-hidden className='size-[23px]' />}
    </button>
}

function CountryFilter({ groups, value, onChange }: {
    groups: CountryGroup[]
    value: string
    onChange: (value: string) => void
}) {
    const scroll = useRef<HTMLDivElement>(null)
    const [edges, setEdges] = useState({ left: false, right: false })
    useLayoutEffect(() => {
        const element = scroll.current
        if (!element) return
        const update = () => setEdges({
            left: element.scrollLeft > 1,
            right: element.scrollLeft + element.clientWidth < element.scrollWidth - 1,
        })
        update()
        element.addEventListener('scroll', update, { passive: true })
        const observer = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(update) : null
        observer?.observe(element)
        return () => {
            element.removeEventListener('scroll', update)
            observer?.disconnect()
        }
    }, [groups])

    const move = (direction: number) => {
        const element = scroll.current
        if (element) element.scrollBy({ left: direction * Math.max(180, element.clientWidth * 0.75), behavior: 'smooth' })
    }

    return <div className='flex min-w-0 max-w-full items-center gap-1'>
        <button type='button' aria-label='Страны левее' title='Страны левее'
            disabled={!edges.left} onClick={() => move(-1)}
            className='mb-2 flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-full bg-fill text-tint disabled:cursor-default disabled:opacity-30'>
            <IconChevronLeft aria-hidden className='size-5' />
        </button>
        <div ref={scroll} role='group' aria-label='Страна' tabIndex={0}
            className='country-filter-scroll flex min-w-0 flex-1 gap-2 overflow-x-auto overscroll-x-contain pb-2 focus-visible:outline-2 focus-visible:outline-tint'>
            {['all', ...groups.map(group => group.code)].map(code => <button key={code} type='button'
                aria-pressed={code === value} onClick={() => onChange(code)}
                className={cn('min-h-9 shrink-0 cursor-pointer select-none rounded-full px-4 text-[15px] tracking-[-0.24px] transition-colors',
                    code === value ? 'bg-white font-semibold text-black' : 'border border-white/12 bg-white/6 font-medium hover:bg-white/10')}>
                {code === 'all' ? 'Все' : countryLabel(code) || 'Без страны'}
            </button>)}
        </div>
        <button type='button' aria-label='Страны правее' title='Страны правее'
            disabled={!edges.right} onClick={() => move(1)}
            className='mb-2 flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-full bg-fill text-tint disabled:cursor-default disabled:opacity-30'>
            <IconChevronRight aria-hidden className='size-5' />
        </button>
    </div>
}

function CountryCatalog({ groups, rowProps, probeBusy, isPendingGroup, onCheckGroup }: {
    groups: CountryGroup[]
    rowProps: (server: Server) => React.ComponentProps<typeof ServerRow>
    probeBusy: boolean
    isPendingGroup: (code: string) => boolean
    onCheckGroup: (code: string) => void
}) {
    const grid = useRef<HTMLDivElement>(null)
    useLayoutEffect(() => {
        const catalog = grid.current
        if (!catalog || typeof ResizeObserver === 'undefined') return
        // Size each span to its card so the next country fits below the shorter column.
        const sizeCard = (card: HTMLElement, height: number) => {
            const rows = Math.ceil((height + 12) / 8)
            card.style.setProperty('--country-span', String(rows))
        }
        const observer = new ResizeObserver(entries => {
            for (const entry of entries) {
                sizeCard(entry.target as HTMLElement, entry.borderBoxSize?.[0]?.blockSize ?? entry.target.getBoundingClientRect().height)
            }
        })
        const cards = Array.from(catalog.querySelectorAll<HTMLElement>(':scope > section'))
        const heights = cards.map(card => card.getBoundingClientRect().height)
        cards.forEach((card, index) => {
            sizeCard(card, heights[index])
            observer.observe(card)
        })
        catalog.dataset.packed = 'true'
        return () => {
            observer.disconnect()
            delete catalog.dataset.packed
        }
    }, [groups])

    return <div ref={grid} className='country-catalog grid min-w-0 items-start gap-3 lg:grid-cols-2 lg:gap-x-4'>
        {groups.map(group => <Group key={group.code}
            className='[&>h2]:text-[15px] [&>h2]:font-semibold [&>h2]:normal-case [&>h2]:text-foreground'
            title={<span className='flex min-w-0 items-center justify-between gap-2'>
                <span>{countryLabel(group.code) || 'Страна не определена'} · {group.list.length}</span>
                <ProbeButton label={`Обновить пинг группы ${countryLabel(group.code) || 'Без страны'}`}
                    disabled={probeBusy} measuring={isPendingGroup(group.code)} onClick={() => onCheckGroup(group.code)} />
            </span>}>
            {group.list.map(server => <ServerRow key={server.id} {...rowProps(server)} />)}
        </Group>)}
    </div>
}

function groupServers(servers: Server[], order: CountryOrder) {
    const groups = new Map<string, CountryGroup>()
    for (const server of servers) {
        if (server.protocol === 'xray-profile') continue
        const code = serverCountry(server) || OTHER
        let group = groups.get(code)
        if (!group) {
            group = { code, list: [], bestLatency: Infinity }
            groups.set(code, group)
        }
        group.list.push(server)
        // The catalogue receives the completed HTTPS run in one batch. Live
        // results update each row separately and never enter the group rank.
        if (server.probe_kind === 'https' && !server.check_error && server.latency_ms > 0) {
            group.bestLatency = Math.min(group.bestLatency, server.latency_ms)
        }
    }
    for (const group of groups.values()) group.list.sort(byLatency)
    return [...groups.values()].sort((a, b) => {
        if (a.code === b.code) return 0
        if (a.code === OTHER) return 1
        if (b.code === OTHER) return -1
        if (order === 'latency' && a.bestLatency !== b.bestLatency) {
            return a.bestLatency - b.bestLatency
        }
        const byName = countryCollator.compare(countryName(a.code), countryName(b.code))
            || countryCollator.compare(a.code, b.code)
        return order === 'name-desc' ? -byName : byName
    })
}

function byLatency(a: Server, b: Server) {
    if (a.active !== b.active) return a.active ? -1 : 1
    const la = a.latency_ms < 0 ? Infinity : a.latency_ms || Infinity
    const lb = b.latency_ms < 0 ? Infinity : b.latency_ms || Infinity
    return la - lb
}

function ProtocolBadge({ protocol, className = 'ml-2 align-middle' }: { protocol: string; className?: string }) {
    const label = ['hysteria', 'hysteria2', 'hy2'].includes(
        protocol.toLowerCase(),
    )
        ? 'Hysteria2'
        : protocol === 'xray-profile' ? 'Профиль' : protocol.toUpperCase()
    return (
        <Badge variant='secondary' className={cn('text-[11px]', className)}>
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

// What a row says about its last check: the router's own probe for a pool
// server, the result of a check running now, or the panel's last check.
type CheckInfo = { latency: number; error?: string; failed: boolean; at?: string; by: 'router' | 'panel' | 'none' }

function checkInfo(server: Server | undefined, node?: PoolNode, live?: number): CheckInfo {
    if (node?.router_latency_ms !== undefined) {
        const ms = node.router_latency_ms
        return { latency: ms, failed: ms < 0, at: isSet(node.router_checked_at) ? node.router_checked_at : undefined, by: 'router' }
    }
    if (live !== undefined) return { latency: live, failed: live < 0, at: new Date().toISOString(), by: 'panel' }
    if (server?.probe_kind === 'https') {
        return {
            latency: server.check_error ? 0 : server.latency_ms,
            error: server.check_error || undefined,
            failed: !!server.check_error || server.latency_ms < 0,
            at: isSet(server.last_checked) ? server.last_checked : undefined,
            by: 'panel',
        }
    }
    return { latency: server ? 0 : node?.latency_ms ?? 0, failed: false, by: 'none' }
}

function checkHint(check: CheckInfo) {
    if (!check.at) return 'Сервер ещё не проверялся'
    const clock = new Date(check.at).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
    const what = check.by === 'router'
        ? check.failed ? 'Роутер не получил ответа' : 'Роутер проверил'
        : check.failed ? 'Не ответил на проверку' : 'Проверен'
    return `${what} ${agoLabel(check.at)}, в ${clock}`
}

// One server in a list: the name with its protocol and status chips, the
// subscription and the provider's note on their own lines; the number and the
// check time under each other on the right, the gauge centred at the edge.
// The whole row selects the server; hints and the gauge keep their own taps.
function ServerCard({ title, titleMuted, chips, source, note, noteTitle, check, measuring,
    highlighted, selectLabel, onSelect, selectDisabled, probe }: {
    title: React.ReactNode
    titleMuted?: boolean
    chips: React.ReactNode
    source?: string
    note?: string
    noteTitle?: string
    check: CheckInfo
    measuring: boolean
    highlighted?: boolean
    selectLabel: string
    onSelect: () => void
    selectDisabled: boolean
    probe?: { label: string; disabled: boolean; onCheck: () => void }
}) {
    // A row without a provider's note is two lines high.
    const rows = 1 + (source ? 1 : 0) + (note ? 1 : 0)
    const timeRow = Math.max(rows, 2)
    const noteRow = source ? 3 : 2

    return (
        <div className={cn('relative grid min-h-[52px] grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-x-1.5 gap-y-0.5 py-2.5',
            highlighted && '-mx-2 my-1 rounded-xl bg-white/[0.05] px-2 ring-[1.5px] ring-[#8b7cff]')}>
            <button type='button' aria-label={selectLabel} onClick={onSelect} disabled={selectDisabled}
                className='absolute inset-0 cursor-pointer rounded-xl focus-visible:outline-2 focus-visible:outline-tint disabled:cursor-default' />
            <div className='flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1' style={{ gridColumn: 1, gridRow: 1 }}>
                <span className={cn('min-w-0 break-words text-[17px] leading-snug tracking-[-0.43px]', titleMuted && 'text-muted-foreground')}>
                    {title}
                </span>
                {/* One block: when the name leaves no room it moves to the next line whole. */}
                <span className='inline-flex shrink-0 items-center gap-1'>{chips}</span>
            </div>
            {source && <span className='min-w-0 truncate text-[13px] text-muted-foreground' style={{ gridColumn: 1, gridRow: 2 }}>
                {source}
            </span>}
            {note && <span className='min-w-0 truncate text-[13px] text-muted-foreground' title={noteTitle}
                style={{ gridColumn: 1, gridRow: noteRow }}>
                {note}
            </span>}
            <span className='justify-self-end' style={{ gridColumn: 2, gridRow: 1 }}>
                {check.error && !measuring
                    ? <span className='inline-flex w-[4.25rem] justify-end'>
                        <Hint label={check.error} round={false} className='text-destructive'>
                            <IconAlertTriangle aria-hidden className='size-[18px]' stroke={2.2} />
                        </Hint>
                    </span>
                    : <Latency measuring={measuring} ms={check.latency} />}
            </span>
            {!measuring && (
                <span className='justify-self-end' style={{ gridColumn: 2, gridRow: timeRow }}>
                    <Hint round={false} label={checkHint(check)}
                        className={cn('text-[13px] tabular-nums', check.failed ? 'text-destructive' : 'text-muted-foreground')}>
                        {check.at ? timeAgo(check.at) : 'не проверен'}
                    </Hint>
                </span>
            )}
            {probe && <span className='self-center' style={{ gridColumn: 3, gridRow: `1 / span ${timeRow}` }}>
                <ProbeButton label={probe.label} disabled={probe.disabled} measuring={measuring} onClick={probe.onCheck} />
            </span>}
        </div>
    )
}

function ServerRow({
    server,
    routerNode,
    liveLatency,
    measuring,
    countryExcluded,
    busy,
    probeBusy,
    onCheck,
    onSelect,
}: {
    server: Server
    routerNode?: PoolNode
    measuring: boolean
    liveLatency?: number
    countryExcluded: boolean
    busy: boolean
    probeBusy: boolean
    onCheck: () => void
    onSelect: () => void
}) {
    const inPool = !!server.pool_tag && !countryExcluded
    return (
        <ServerCard
            title={withCountryFlag(server.name, serverCountry(server))}
            chips={<>
                <ProtocolBadge protocol={server.protocol} className='' />
                {inPool && <Hint label='В автовыборе: роутер сам ведёт трафик через самый быстрый сервер пула'>
                    <IconWand aria-hidden className='size-[13px]' stroke={2.2} />
                </Hint>}
                {countryExcluded && <Hint label='Локация исключена из автовыбора. Этот сервер можно выбрать только вручную'>
                    <IconBan aria-hidden className='size-[13px]' stroke={2.2} />
                </Hint>}
                {server.active && <Hint label='Выбран: через этот сервер идут остальные сайты' className='text-tint'>
                    <IconCheck aria-hidden className='size-[13px]' stroke={3} />
                </Hint>}
            </>}
            source={server.source_name}
            note={shortNote(server.description) || undefined}
            noteTitle={server.description}
            check={checkInfo(server, routerNode, liveLatency)}
            measuring={measuring}
            highlighted={server.active}
            selectLabel={`Выбрать сервер ${server.name}`}
            onSelect={onSelect}
            selectDisabled={busy || server.active}
            probe={{ label: `Обновить пинг сервера ${server.name}`, disabled: probeBusy, onCheck }}
        />
    )
}
