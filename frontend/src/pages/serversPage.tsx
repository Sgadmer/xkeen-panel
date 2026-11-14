import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
    IconActivityHeartbeat,
    IconCheck,
    IconChevronRight,
    IconLink,
    IconLoader2,
    IconLayersLinked,
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
import { ServerAutomation } from '@/components/serverAutomation'
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
    countryName,
    countryLabel,
    countryExcluded,
    latencyTone,
    scopeLabel,
    serverCountry,
    timeAgo,
    toneText,
    unavailableCountryReason,
    serverDisplayName,
} from '@/lib/format'
import { cn } from '@/lib/utils'
import { serverPathDetail } from '@/lib/serverPath'
import { importWarnings, safeNotice } from '@/lib/subscription'
import type { AutoScope, Server } from '@/types'

const OTHER = '—'

// One list on a phone, separate cards side by side on a desktop
const TILE = 'lg:rounded-card lg:bg-card lg:px-4'

type CountryGroup = { code: string; list: Server[]; bestLatency: number }
type CountryOrder = 'name-asc' | 'name-desc' | 'latency'

type Tab = 'pool' | 'all'

const TAB_KEY = 'servers_tab'
const COUNTRY_ORDER_KEY = 'servers_country_order'
const countryCollator = new Intl.Collator('ru', { sensitivity: 'base' })

function countryPoolOption(scope: AutoScope, avoided: string[]) {
    const name = scopeLabel(scope)
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

function savedCountryOrder(): CountryOrder {
    try {
        return countryOrder(localStorage.getItem(COUNTRY_ORDER_KEY))
    } catch {
        return 'name-asc'
    }
}

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
    const sources = useServerSources().data
    const status = useStatus().data
    const mihomo = status?.core === 'mihomo' || pool?.core === 'mihomo'
    const poolCatalog = useMultiPools(mihomo)
    const multipools = poolCatalog.data?.pools ?? []
    const scopes = poolCatalog.data?.scopes ?? []
    const selectedScope = scopes.find(item => item.id === pool?.auto_scope_id)
    const allLocations = scopes.find(item => item.kind === 'all')
    const countries = scopes.filter(scope => scope.kind === 'country')
        .sort((a, b) => countryCollator.compare(countryName(a.country), countryName(b.country)))
    const availableCountries = countries.filter(scope => scope.member_count > 0)
    const unavailableCountries = countries.filter(scope => !scope.member_count
        && (scope.unavailable_reason !== 'no_servers' || scope.id === selectedScope?.id))
    const customScopes = scopes.filter(scope => scope.kind === 'custom')
    const providerModes = servers.filter(s => s.protocol === 'xray-profile')
    const settings = usePanelSettings().data
    const avoidCountries = settings?.avoid_countries ?? []
    const fullPath = settings?.show_full_path !== false
    const sites = useSites().data
    const subscription = useSubscription().data
    const {
        select,
        pin,
        auto,
        refreshSubscription,
        setCountry,
        setScope,
        setPoolLimit,
    } = useServerActions()
    const routeBusy = select.isPending || pin.isPending || auto.isPending || setScope.isPending || setPoolLimit.isPending
    const { check, checking, error: checkError, progress, isPendingServer, latencyFor } = useStreamLatency()
    const [query, setQuery] = useState('')
    const [country, setCountryFilter] = useState('all')
    const [order, setOrder] = useState<CountryOrder>(savedCountryOrder)
    const [catalogSheet, setCatalogSheet] = useState<'sources' | 'pools' | null>(null)
    const [editingPool, setEditingPool] = useState<string | null>(null)
    const [tab, setTabState] = useState<Tab>(savedTab)
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

    const isPool = pool?.mode === 'pool'
    const canChoosePool = isPool || (mihomo && scopes.length > 0)
    const view: Tab = canChoosePool ? tab : 'all'
    const setTab = (next: Tab) => {
        setTabState(next)
        try {
            localStorage.setItem(TAB_KEY, next)
        } catch {}
    }

    const catalogGroups = useMemo(() => groupServers(servers, order), [servers, order])
    const groups = useMemo(() => catalogGroups
        .filter(g => country === 'all' || g.code === country)
        .map(g => ({ ...g, list: g.list.filter(s => matches(query, s.name, g.code, s.source_name)) }))
        .filter(g => g.list.length > 0), [catalogGroups, country, query])

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
                    latency: server
                        ? server.probe_kind === 'https'
                            ? server.latency_ms
                            : 0
                        : n.latency_ms,
                    current: n.tag === pool?.current_tag,
                    excluded: !!n.excluded_until,
                }
            })
            .filter(r => matches(query, r.node.name, r.country, r.source))
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
        path: serverPathDetail(s, fullPath, s.name),
        countryExcluded: countryExcluded(s, avoidCountries),
        busy: routeBusy,
        measuring: isPendingServer(s.id),
        liveLatency: latencyFor(s.id),
        onSelect: () => select.mutate(s.id),
        onSetCountry: (c: string) =>
            setCountry.mutate({ id: s.id, country: c }),
    })

    const isAuto = pool?.selection_kind ? pool.selection_kind === 'auto' : isPool && !pool?.pin_manual
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
                                : 'Проверить доступность и задержку серверов'
                        }
                        onClick={check}
                        disabled={checking}
                    />
                </div>
            )}
        </div>
    )

    const profiles = providerModes.filter(s => matches(query, s.name, serverCountry(s), s.source_name))
    const providerCard = profiles.length > 0 && (
        <Group title='Режимы провайдера' footer='Это готовые варианты из вашей подписки. Какие серверы входят в каждый вариант и как они выбираются, решает поставщик VPN.'>
            {profiles.map(server => {
                const ms = latencyFor(server.id) ?? server.latency_ms
                const measured = server.probe_kind === 'https' || latencyFor(server.id) !== undefined
                return <Row key={server.id} label={server.name}
                    hint={[server.source_name, `${server.profile_nodes ?? 0} серверов`, server.active && 'Выбран'].filter(Boolean).join(' · ')}
                    onClick={() => select.mutate(server.id)} disabled={routeBusy || server.active}
                    trailing={<Latency measuring={isPendingServer(server.id)} ms={measured ? ms : 0} />} />
            })}
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
                            },
                            { value: 'all', label: `Все серверы · ${servers.length}` },
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
                                    ? 'Пул — это список серверов для выбора. Роутер проверяет, какой из них быстрее отвечает, и переключается сам, если сервер перестал работать.'
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
                                    {availableCountries.length > 0 && <optgroup label='Пулы стран'>{availableCountries.map(item => countryPoolOption(item, avoidCountries))}</optgroup>}
                                    {customScopes.length > 0 && <optgroup label='Мультипулы'>
                                        {customScopes.map(item => <option key={item.id} value={item.id} disabled={!item.member_count}>{scopeLabel(item)} · {item.member_count || 'нет подходящих серверов'}</option>)}
                                    </optgroup>}
                                    {unavailableCountries.length > 0 && <optgroup label='Недоступные страны'>{unavailableCountries.map(item => countryPoolOption(item, avoidCountries))}</optgroup>}
                                </select>
                              </div>
                              <p id='auto-pool-scope-hint' className='mt-1 text-[13px] text-muted-foreground'>
                                  Выберите страну, и роутер будет искать быстрый сервер в ней среди всех ваших подписок.
                              </p>
                            </div>}
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
                                    name={serverDisplayName(r.node.name, r.country)}
                                    protocol={r.protocol}
                                    source={r.source}
                                    path={serverPathDetail(r.server ?? r.node, fullPath, r.node.name)}
                                    latency={latencyFor(r.node.server_id) ?? r.latency}
                                    measuring={isPendingServer(r.node.server_id)}
                                    current={r.current}
                                    excludedUntil={r.node.excluded_until}
                                    countryExcluded={r.server ? countryExcluded(r.server, avoidCountries) : avoidCountries.includes(r.country ?? '')}
                                    busy={routeBusy}
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
                        <ServerAutomation />
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
                        {tiles}
                    </div>
                </div>
            )}

            {view === 'all' && (
                <>
                    {tiles}
                    <ServerAutomation />
                    {providerCard}

                    {servers.length > 0 && (
                        <div className='flex flex-col gap-3'>
                            <SearchField
                                value={query}
                                onChange={setQuery}
                                className='lg:hidden'
                            />
                            <label className='flex flex-wrap items-center gap-x-3 gap-y-1 text-[15px]'>
                                <span>Порядок стран</span>
                                <select value={order}
                                    className='min-h-10 max-w-full rounded-xl border border-white/10 bg-fill px-2'
                                    onChange={event => {
                                        const next = countryOrder(event.target.value)
                                        setOrder(next)
                                        try { localStorage.setItem(COUNTRY_ORDER_KEY, next) } catch {}
                                    }}>
                                    <option value='name-asc'>По названию (А–Я)</option>
                                    <option value='name-desc'>По названию (Я–А)</option>
                                    <option value='latency'>По наименьшему пингу</option>
                                </select>
                            </label>
                            <div
                                role='group'
                                aria-label='Страна'
                                className='-mx-4 flex gap-2 overflow-x-auto px-4 [mask-image:linear-gradient(to_right,transparent,black_16px,black_calc(100%-40px),transparent)] [-webkit-mask-image:linear-gradient(to_right,transparent,black_16px,black_calc(100%-40px),transparent)] [scrollbar-width:none]'
                            >
                                {['all', ...catalogGroups.map(g => g.code)].map(c => (
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
                                            : countryLabel(c) || 'Без страны'}
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    <CountryCatalog groups={groups} rowProps={rowProps} />

                    {mihomo && multipools.some(item => matches(query, item.name)) && (
                        <Group title='Мультипулы'>
                            {multipools.filter(item => matches(query, item.name)).map(item => <Row key={item.id} label={item.name}
                                hint={`${item.member_count} серверов${pool?.auto_scope_id === item.id && isAuto ? ' · Основной маршрут' : ''}`}
                                onClick={() => { setEditingPool(item.id); setCatalogSheet('pools') }}
                                trailing={<IconChevronRight className='size-4 text-label-tertiary' />} />)}
                        </Group>
                    )}
                    {servers.length > 0 && groups.length === 0 && !profiles.length && !multipools.some(item => matches(query, item.name)) && (
                        <p className='px-4 text-[15px] text-muted-foreground'>
                            Ничего не нашлось
                        </p>
                    )}
                </>
            )}

            <SourcesSheet open={catalogSheet === 'sources'} onClose={() => setCatalogSheet(null)} />
            <MultiPoolsSheet initialId={editingPool} open={catalogSheet === 'pools'} onClose={() => setCatalogSheet(null)} />
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

function matches(query: string, name: string, country?: string, source?: string) {
    const q = query.trim().toLowerCase()
    return (
        !q ||
        name.toLowerCase().includes(q) ||
        !!source?.toLowerCase().includes(q) ||
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
    protocol,
    source,
    path,
    latency,
    measuring,
    current,
    excludedUntil,
    countryExcluded,
    busy,
    onSelect,
}: {
    name: string
    protocol?: string
    source?: string
    path: string
    latency: number
    measuring: boolean
    current: boolean
    excludedUntil?: string
    countryExcluded: boolean
    busy: boolean
    onSelect: () => void
}) {
    const notes = [
        source,
        countryExcluded && 'Страна исключена в разделе «Автоматика»',
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
                {path && <span className='mt-0.5 block text-[13px] text-muted-foreground'>{path}</span>}
            </span>
            <Latency measuring={measuring} ms={latency} />
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

function Latency({ measuring, ms }: { measuring: boolean; ms: number }) {
    if (measuring) return <span className='inline-flex shrink-0 items-center text-tint' role='img' aria-label='Проверяем задержку'>
        <IconLoader2 aria-hidden className='size-4 motion-safe:animate-spin' />
    </span>
    return <span className={cn('shrink-0 text-right text-[15px] tabular-nums', toneText[latencyTone(ms)])}>
        {ms > 0 ? `${ms} мс` : ms < 0 ? <span aria-label='Нет ответа' title='Нет ответа'>—</span> : ''}
    </span>
}

function CountryCatalog({ groups, rowProps }: {
    groups: CountryGroup[]
    rowProps: (server: Server) => React.ComponentProps<typeof ServerRow>
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
            title={`${countryLabel(group.code) || 'Страна не определена'} · ${group.list.length}`}>
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

function statusOf(server: Server, countryExcluded: boolean) {
	if (server.check_error) return { label: server.check_error, className: 'text-destructive' }
    if (server.active) return { label: 'Выбран', className: 'text-tint' }
    if (server.probe_kind !== 'https')
        return { label: 'Не проверен', className: 'text-muted-foreground' }
    if (server.latency_ms === -1)
        return { label: 'Не отвечает', className: 'text-destructive' }
    if (server.pool_tag && !countryExcluded)
        return { label: 'В автовыборе', className: 'text-muted-foreground' }
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
    path,
    liveLatency,
    measuring,
    countryExcluded,
    busy,
    onSelect,
    onSetCountry,
}: {
    server: Server
    path: string
    measuring: boolean
    liveLatency?: number
    countryExcluded: boolean
    busy: boolean
    onSelect: () => void
    onSetCountry: (country: string) => void
}) {
    const [editing, setEditing] = useState(false)
    const [value, setValue] = useState(serverCountry(server))
    const status = statusOf(liveLatency === undefined ? server : { ...server, probe_kind: 'https', latency_ms: liveLatency, check_error: undefined }, countryExcluded)
    const measured = liveLatency ?? (server.probe_kind === 'https' ? server.latency_ms : 0)

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
                        {serverDisplayName(server.name, serverCountry(server))}
                        <ProtocolBadge protocol={server.protocol} />
                    </span>
                    {server.source_name && <span className='mt-0.5 block text-[13px] text-muted-foreground'>{server.source_name}</span>}
                    {path && <span className='mt-0.5 block text-[13px] text-muted-foreground'>{path}</span>}
                    {!measuring && status && (
                        <span
                            className={cn(
                                'mt-0.5 block text-[13px]',
                                status.className,
                            )}
                        >
                            {status.label}
                        </span>
                    )}
                    {countryExcluded && (
                        <span className='mt-0.5 block text-[13px] text-muted-foreground'>
                            Страна исключена из автовыбора · ручной выбор
                        </span>
                    )}
                </span>
                <Latency measuring={measuring} ms={measured} />
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
