import { type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
    IconDeviceDesktop,
    IconDownload,
    IconRefresh,
    IconWorld,
} from '@tabler/icons-react'
import { Group, IconTile, Row, Switch } from '@/components/ios'
import { useSetupState } from '@/pages/welcomePage'
import { Logo } from '@/components/logo'
import {
    useDevices,
    useLogs,
    useMultiPools,
    usePanelSettings,
    usePool,
    useServers,
    useStatus,
    useSubscription,
    useUpdate,
} from '@/hooks/usePanelData'
import { useServerActions } from '@/hooks/useServerActions'
import {
    countryName,
    countryFlag,
    panelEvents,
    scopeLabel,
    serverCountry,
    statusInfo,
    timeAgo,
    toneDot,
    toneFill,
    toneText,
} from '@/lib/format'
import { cn } from '@/lib/utils'
import { serverPathDetail } from '@/lib/serverPath'

export function HomePage() {
    const status = useStatus().data
    const servers = useServers().data ?? []
    const pool = usePool().data
    const subscription = useSubscription().data
    const devices = useDevices().data
    const update = useUpdate().data
    const logs = useLogs().data ?? []
    const fullPath = usePanelSettings().data?.show_full_path !== false
    const { auto, pin } = useServerActions()
    const setup = useSetupState().data

    const info = statusInfo(status)
    const isPool = pool?.mode === 'pool'
    const isAuto = pool?.selection_kind ? pool.selection_kind === 'auto' : isPool && !pool?.pin_manual
    const catalog = useMultiPools(status?.core === 'mihomo').data
    const scope = catalog?.scopes?.find(item => item.id === pool?.auto_scope_id)
    const node = pool?.nodes?.find(item => item.tag === pool.current_tag)
    const current = node ? servers.find(s => s.id === node.server_id)
        : pool?.selection_kind ? servers.find(s => s.target_id === pool.current_tag && (!pool.source_name || s.source_name === pool.source_name))
        : servers.find(s => s.active)
    const selective = pool?.selective ?? status?.selective
    const actualName = pool?.current_name ?? status?.current_server
    const direct = actualName === 'DIRECT'
    const blocked = actualName === 'REJECT'
    const code = direct || blocked ? '' : serverCountry(current ?? node)
    const source = pool?.source_name || ((!pool?.selection_kind || !['native', 'auto'].includes(pool.selection_kind)) ? current?.source_name : undefined)
    const awaitingMember = pool?.selection_kind === 'auto' && !pool.current_tag
    const path = !direct && !blocked && !awaitingMember && serverPathDetail(current, fullPath, countryName(code))
    const endpoint = direct ? 'Прямое подключение' : blocked ? 'Маршрут заблокирован' : awaitingMember ? 'Пул проверяет доступные узлы' : current?.name || node?.name || actualName
    const mode = pool?.selection_kind ?? (isAuto ? 'auto' : 'manual')
    const route = mode === 'auto'
        ? 'Автовыбор · ' + (scope ? scopeLabel(scope) : pool?.selection_name || 'Общий пул')
        : mode === 'replacement' ? 'Автоматическая замена · сервер той же страны'
        : mode === 'native' ? 'Группа провайдера · ' + (pool?.selection_name || 'По правилам подписки')
        : mode === 'profile' || !pool?.selection_kind && current?.protocol === 'xray-profile' ? 'Профиль провайдера · ' + (pool?.selection_name || current?.name || '')
        : 'Сервер выбран вручную'
    const events = panelEvents(logs, 5)

    const inVpn = devices?.devices.filter(d => d.vpn).length ?? 0
    const online = devices?.devices.filter(d => d.active).length ?? 0

    const toggleAuto = (next: boolean) => {
        if (next) auto.mutate()
        else if (pool?.current_tag) pin.mutate(pool.current_tag)
    }

    return (
        <>
            <header className='flex items-center justify-between gap-3 px-1 lg:hidden'>
                <div className='flex items-center gap-2.5'>
                    <Logo size={32} />
                    <h1 className='text-[34px] font-bold tracking-[0.37px]'>
                        XKeen
                    </h1>
                </div>
                <StatusPill label={info.label} tone={info.tone} />
            </header>
            <h1 className='hidden px-1 text-[34px] font-bold tracking-[0.37px] lg:block'>
                Главная
            </h1>

            {setup && !setup.complete && (
                <Group>
                    <Row
                        label='Завершите настройку'
                        hint='Осталось несколько шагов, чтобы VPN заработал'
                        tone='tint'
                        to='/welcome'
                    />
                </Group>
            )}

            <div className='grid grid-cols-1 gap-4 lg:grid-cols-2 lg:items-start'>
                <div className='flex flex-col gap-4'>
                    <section className='flex flex-col gap-3.5 rounded-card bg-card p-[18px]'>
                        <div className='flex items-center gap-3.5'>
                            <div className='flex size-14 shrink-0 items-center justify-center rounded-2xl bg-white/8 text-[22px] font-bold tracking-[-0.5px]'>
                                {countryFlag(code) || code || '—'}
                            </div>
                            <div className='min-w-0'>
                                <div className='truncate text-[22px] font-bold tracking-[-0.26px]'>
                                    {countryName(code) ||
                                        endpoint ||
                                        'Сервер не выбран'}
                                </div>
                                <div className='truncate text-[15px] tracking-[-0.24px] text-muted-foreground'>
                                    {endpoint}
                                    {!direct && !blocked && !awaitingMember && status &&
                                        status.latency_ms > 0 &&
                                        ` · ${status.latency_ms} мс`}
                                </div>
                            </div>
                        </div>
                        {!!pool && <div className='grid gap-1 border-t border-white/10 pt-2.5 text-[14px]'>
                            <p className='break-words'><span className='text-muted-foreground'>{selective ? 'Маршрут для Re:filter' : 'Основной маршрут'} · </span>{route}</p>
                            {selective && <p className='text-muted-foreground'>После правил сервисов и исключений адреса из списка идут по выбранному маршруту. Остальные адреса открываются напрямую.</p>}
                            {source && <p className='break-words'><span className='text-muted-foreground'>Подписка · </span>{source}</p>}
                            {path && <p className='break-words'>{path}</p>}
                        </div>}
                        {isPool && (
                            <div className='flex min-h-11 items-center gap-3 border-t border-white/10 pt-2.5'>
                                <div className='min-w-0 flex-1'>
                                    <div className='text-[17px] tracking-[-0.43px]'>
                                        Автоматически выбирать сервер
                                    </div>
                                    <div className='mt-0.5 text-[13px] text-muted-foreground'>
                                        {pool?.pin_note || (isAuto ? `Кандидатов в пуле: ${pool?.nodes?.length ?? 0}` : 'При включении панель выберет сервер из пула')}
                                    </div>
                                </div>
                                <Switch
                                    checked={isAuto}
                                    onChange={toggleAuto}
                                    label='Автоматически выбирать сервер'
                                    disabled={
                                        auto.isPending ||
                                        pin.isPending ||
                                        !pool?.api_available || (isAuto && !pool?.current_tag)
                                    }
                                />
                            </div>
                        )}
                    </section>

                    <div className='grid grid-cols-2 gap-3.5'>
                        <Widget
                            to='/servers'
                            icon={
                                <IconTile color='#0a84ff'>
                                    <IconWorld
                                        className='size-[17px]'
                                        stroke={2.2}
                                    />
                                </IconTile>
                            }
                            value={subscription?.server_count ?? 0}
                            caption={
                                isPool
                                    ? `серверов · ${pool?.pool_tags?.length ?? 0} в пуле`
                                    : 'серверов'
                            }
                        />
                        <Widget
                            to='/devices'
                            icon={
                                <IconTile color='#30d158'>
                                    <IconDeviceDesktop
                                        className='size-[17px]'
                                        stroke={2.2}
                                    />
                                </IconTile>
                            }
                            value={
                                <>
                                    {inVpn}{' '}
                                    <span className='text-[15px] font-normal text-muted-foreground'>
                                        из {devices?.devices.length ?? 0}
                                    </span>
                                </>
                            }
                            caption={
                                devices
                                    ? `через VPN · ${online} в сети`
                                    : 'устройств'
                            }
                        />
                        <Widget
                            to='/servers'
                            icon={
                                <IconTile color='#ff9f0a'>
                                    <IconRefresh
                                        className='size-[17px]'
                                        stroke={2.2}
                                    />
                                </IconTile>
                            }
                            value={timeAgo(subscription?.last_updated) || '—'}
                            caption='с обновления подписки'
                        />
                        <Widget
                            to='/settings/update'
                            icon={
                                <IconTile color='#6366f1'>
                                    <IconDownload
                                        className='size-[17px]'
                                        stroke={2.2}
                                    />
                                </IconTile>
                            }
                            value={status?.panel_version ?? '—'}
                            caption={
                                update?.available && update.latest
                                    ? `доступна ${update.latest.tag}`
                                    : update?.auto
                                      ? `обновится в ${String(update.auto_hour).padStart(2, '0')}:00`
                                      : 'версия панели'
                            }
                        />
                    </div>
                </div>

                <section className='flex flex-col gap-1.5'>
                    <h2 className='px-4 text-[13px] uppercase tracking-[-0.08px] text-muted-foreground'>
                        События
                    </h2>
                    <div className='divide-y divide-white/10 rounded-card bg-card px-4'>
                        {events.length === 0 && (
                            <p className='py-3 text-[15px] text-muted-foreground'>
                                Пока ничего не происходило
                            </p>
                        )}
                        {events.map((e, i) => (
                            <div
                                key={i}
                                className='flex gap-3 py-3 text-[15px] leading-snug tracking-[-0.24px]'
                            >
                                <span className='shrink-0 tabular-nums text-muted-foreground'>
                                    {e.time}
                                </span>
                                <span className='min-w-0'>{e.text}</span>
                            </div>
                        ))}
                    </div>
                </section>
            </div>
        </>
    )
}

function StatusPill({
    label,
    tone,
}: {
    label: string
    tone: keyof typeof toneText
}) {
    return (
        <div
            className={cn(
                'flex min-h-9 items-center gap-1.5 rounded-full px-3.5 text-[15px] font-semibold tracking-[-0.24px]',
                toneFill[tone],
                toneText[tone],
            )}
        >
            <span className={cn('size-2 rounded-full', toneDot[tone])} />
            {label}
        </div>
    )
}

function Widget({
    to,
    icon,
    value,
    caption,
}: {
    to: string
    icon: ReactNode
    value: ReactNode
    caption: string
}) {
    return (
        <Link
            to={to}
            className='flex min-h-28 flex-col gap-2 rounded-card bg-card p-4'
        >
            {icon}
            <span className='truncate text-[22px] font-bold tracking-[-0.26px]'>
                {value}
            </span>
            <span className='text-[13px] leading-snug text-muted-foreground'>
                {caption}
            </span>
        </Link>
    )
}
