import { IconWorld } from '@tabler/icons-react'
import { Group, Row } from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { ServiceLogo } from '@/components/serviceLogo'
import { countryName, withCountryFlag } from '@/lib/format'
import type { JournalEntry, JournalKind } from '@/lib/trafficHistory'

export type ViewEntry = JournalEntry & { pool_current?: { name?: string; country?: string; source?: string }; reason?: string }

const clock = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const stamp = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const count = new Intl.NumberFormat('ru-RU')
export const kindLabels: Record<JournalKind, string> = { connection: 'Соединение', kill_switch: 'Kill switch', quic: 'QUIC', error: 'Ошибка' }

export function moment(value?: string) {
    const at = value ? Date.parse(value) : NaN
    return Number.isFinite(at) && at > 0 ? at : 0
}
export function timeLabel(value: string, withDate = false) {
    const at = moment(value)
    return at ? (withDate ? stamp : clock).format(at) : '—'
}
export function destination(entry: ViewEntry) {
    const host = entry.host.includes(':') && entry.port ? '[' + entry.host + ']' : entry.host
    return host ? host + (entry.port ? ':' + entry.port : '') : kindLabels[entry.kind]
}

export function outcome(entry: ViewEntry) {
    if (entry.kind === 'kill_switch') return { label: 'Kill switch', className: 'bg-warning/10 text-warning' }
    if (entry.kind === 'quic') return { label: 'QUIC', className: 'bg-fill text-muted-foreground' }
    if (entry.kind === 'error') return { label: 'Ошибка', className: 'bg-destructive/10 text-destructive' }
    if (entry.exit?.kind === 'direct' || entry.route.includes('Напрямую')) return { label: 'Напрямую', className: 'bg-fill text-muted-foreground' }
    if (entry.exit?.kind === 'reject' || entry.route.includes('Блокировка')) return { label: 'Блокировка', className: 'bg-warning/10 text-warning' }
    // A route that is neither direct nor a block goes through a VPN server or
    // pool, even when the server itself was not reported.
    const proxy = entry.exit?.kind === 'server' || !!entry.pool_current || entry.route.length > 0
    return { label: proxy ? 'VPN' : 'Маршрут', className: proxy ? 'bg-tint/10 text-tint' : 'bg-fill text-muted-foreground' }
}

// The route as text, for copying and for the saved file.
export function routeText(flow: ViewEntry, service?: string) {
    const location = flow.exit?.kind === 'server' ? flow.exit : flow.pool_current
    const node = location && (location.name || countryName(location.country))
    const hops = [...flow.route]
    if (node && hops.at(-1) === node) hops.pop()
    if (service && hops[0] !== service) hops.unshift(service)
    const label = flow.exit?.kind === 'direct' ? 'Напрямую' : flow.exit?.kind === 'reject' ? 'Блокировка' : ''
    if (label && hops.at(-1) !== label) hops.push(label)
    return [...hops, node].filter(Boolean).join(' → ')
}

export function FlowRoute({ flow, service, compact = false }: { flow: ViewEntry; service?: string; compact?: boolean }) {
    const location = flow.exit?.kind === 'server' ? flow.exit : flow.pool_current
    const country = countryName(location?.country)
    const node = location && withCountryFlag(location.name || country, location.country)
    const hops = [...flow.route]
    if (node && flow.exit?.kind === 'server' && (hops.at(-1) === location?.name || hops.at(-1) === node)) hops.pop()
    if (service && (hops.length || node)) {
        // Older journal entries carry the former name.
        if ((hops[0] === 'Остальные сайты' || hops[0] === 'Общий маршрут') && (hops.length > 1 || node)) hops.shift()
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

const chip = 'max-w-full cursor-pointer truncate rounded text-left hover:text-tint focus-visible:outline-2 focus-visible:outline-tint'

// One journal row. The address opens the details; the device and the service
// are shortcuts that narrow the journal to themselves.
export function LogCard({ entry, service, withDate, onOpen, onDevice, onService }: {
    entry: ViewEntry; service?: string; withDate: boolean
    onOpen: () => void; onDevice?: () => void; onService?: () => void
}) {
    const status = outcome(entry)
    const target = destination(entry)
    const device = (entry.device_name && entry.device_name !== entry.device ? entry.device_name + ' · ' : '') + (entry.device || 'Устройство')
    return <article className='min-w-0 border-b border-white/10 py-2 last:border-b-0' data-log-kind={entry.kind}>
        <div className='flex min-w-0 items-center gap-2 leading-5'>
            {entry.service_id && onService
                ? <button type='button' onClick={onService} aria-label={`Только сервис ${service ?? entry.service_id}`} title={`Только ${service ?? entry.service_id}`} className='shrink-0 cursor-pointer rounded focus-visible:outline-2 focus-visible:outline-tint'><ServiceLogo id={entry.service_id} className='size-4' /></button>
                : entry.service_id ? <ServiceLogo id={entry.service_id} className='size-4 shrink-0' /> : <IconWorld aria-hidden className='size-4 shrink-0 text-muted-foreground' />}
            <button type='button' onClick={onOpen} aria-label={`Подробнее: ${target}`} title={target}
                className='min-w-0 flex-1 cursor-pointer truncate text-left text-[14px] font-semibold focus-visible:rounded focus-visible:outline-2 focus-visible:outline-tint'>
                {target}
            </button>
            <span className={'shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-4 ' + status.className}>{status.label}</span>
            {(entry.count ?? 1) > 1 && <span className='shrink-0 text-xs tabular-nums text-muted-foreground'>×{count.format(entry.count!)}</span>}
            <time dateTime={entry.at} className='shrink-0 text-[11px] tabular-nums text-muted-foreground'>{timeLabel(entry.at, withDate)}</time>
        </div>
        <p className='flex min-w-0 text-xs leading-4 text-muted-foreground'>
            {onDevice ? <button type='button' onClick={onDevice} title={`Только ${device}`} className={chip}>{device}</button> : <span className='truncate'>{device}</span>}
            {entry.network && <span className='shrink-0'>&nbsp;· {entry.network.toUpperCase()}</span>}
        </p>
        <FlowRoute flow={entry} service={service} compact />
    </article>
}

export function LogDetails({ entry, service, onClose, actions }: {
    entry: ViewEntry | null; service?: string; onClose: () => void
    actions?: { label: string; onClick: () => void; tone?: 'tint' | 'destructive' }[]
}) {
    return <Sheet open={entry !== null} onClose={onClose} title='Запись журнала' closeLabel='Закрыть'>
        {entry && <>
            <Group>
                <Row label='Адрес' hint={<span className='break-all'>{entry.host + (entry.port ? ':' + entry.port : '')}</span>} />
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
            {entry.kind === 'quic' && <p className='px-3 text-sm text-muted-foreground'>Роутер остановил QUIC, приложение перейдёт на обычный HTTPS. Это правило протокола, а не отказ VPN-сервера.</p>}
            {entry.kind === 'kill_switch' && <p className='px-3 text-sm text-warning'>Защищённый VPN-маршрут не ответил. Прямой выход для этого запроса запрещён.</p>}
            {actions && actions.length > 0 && <Group>
                {actions.map(action => <Row key={action.label} label={action.label} tone={action.tone ?? 'tint'} onClick={action.onClick} />)}
            </Group>}
        </>}
    </Sheet>
}
