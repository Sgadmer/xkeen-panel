import { useQuery } from '@tanstack/react-query'
import { IconShieldCheckFilled, IconShieldExclamation } from '@tabler/icons-react'
import { Group, Row } from '@/components/ios'
import { serviceKillSwitch, useKillSwitch } from '@/components/killSwitch'
import { useDevices, useStatus } from '@/hooks/usePanelData'
import { aiServiceIds } from '@/lib/aiServiceGroup'
import { api } from '@/lib/api'
import { countryLabel, plural } from '@/lib/format'

type Route = { kind: 'server' | 'direct' | 'reject' | 'unknown'; name?: string; country?: string; pool?: string }
type Routes = { services: { id: string; name: string; target: string; blocked: boolean; current_route?: Route }[] }
type Firewall = { available: boolean; installed: boolean; ready: boolean }
type Mode = { enabled: boolean; mode?: 'protected' | 'blocklist' | 'custom' }

type Finding = { text: string; hint?: string; to: string }

// One answer to "is everything protected right now": the kill switch, where
// unrecognised traffic goes, and the AI cards. Each weak spot links to the
// place where it is changed.
export function ProtectionSummary() {
    const mihomo = useStatus().data?.core === 'mihomo'
    const policy = useKillSwitch(mihomo).data
    const routes = useQuery({ queryKey: ['protection-routes'], queryFn: () => api.get<Routes>('/api/service-routes'), enabled: mihomo, refetchInterval: 30000 }).data
    const firewall = useQuery({ queryKey: ['claude-api-firewall'], queryFn: () => api.get<Firewall>('/api/service-routes/claude-api-firewall'), enabled: mihomo, refetchInterval: 30000 }).data
    const mode = useQuery({ queryKey: ['routing-blocklist'], queryFn: () => api.get<Mode>('/api/routing/blocklist'), enabled: mihomo, refetchInterval: 60000 }).data
    const devices = useDevices().data
    if (!mihomo) return null
    if (!policy || !routes) return <Group title='Защита'><Row label='Проверяем защиту…' /></Group>

    const cards = aiServiceIds.flatMap(id => routes.services.find(service => service.id === id) ?? [])
    const claude = cards.find(card => card.id === 'claude')
    const findings: Finding[] = []
    if (!policy.enabled) findings.push({ text: 'Общий kill switch выключен', hint: 'При отказе VPN основной маршрут выйдет напрямую.', to: '/settings/protection' })
    if (mode?.enabled) findings.push({ text: 'Неопознанный трафик идёт напрямую', hint: 'Включён режим «только по списку блокировок».', to: '/settings/protection' })
    for (const card of cards) {
        if (card.target === 'direct') findings.push({ text: `${card.name} идёт напрямую`, to: '/services' })
        else if (!serviceKillSwitch(policy, card.id).enabled) findings.push({ text: `Kill switch выключен · ${card.name}`, to: '/services' })
    }
    const claudeGuarded = !!claude && claude.target !== 'direct' && serviceKillSwitch(policy, 'claude').enabled
    if (firewall?.available && !firewall.ready && claudeGuarded) findings.push({ text: 'Фильтр API Claude на роутере не активен', hint: 'Он не выпускает запросы Claude напрямую даже при остановленном VPN.', to: '/services' })
    const servers = new Set(cards.filter(card => card.target && card.target !== 'direct').map(card => card.target))
    if (servers.size > 1) findings.push({ text: 'У AI-карточек разные серверы', hint: 'Один сервер на все четыре снижает риск для аккаунта.', to: '/services' })

    const route = !claude ? '' : claude.blocked || claude.current_route?.kind === 'reject' ? 'заблокирован, VPN не отвечает'
        : !claude.target ? 'VPN не выбран, запросы блокируются'
            : claude.current_route?.kind === 'server' ? [claude.current_route.name, countryLabel(claude.current_route.country)].filter(Boolean).join(' · ') : 'маршрут уточняется'
    const outside = devices?.devices.filter(device => device.active && !device.vpn).length ?? 0
    const good = findings.length === 0

    return <Group title='Защита'>
        <Row
            icon={good ? <IconShieldCheckFilled aria-hidden className='size-7 shrink-0 text-success' /> : <IconShieldExclamation aria-hidden className='size-7 shrink-0 text-warning' />}
            label={good ? 'Защита включена' : `${plural(findings.length, 'Слабое место', 'Слабых места', 'Слабых мест')}: ${findings.length}`}
            hint={good ? 'Kill switch включён, неопознанный трафик идёт через VPN.' : undefined}
            to='/settings/protection' />
        {findings.map(finding => <Row key={finding.text} label={<span className='text-warning'>{finding.text}</span>} hint={finding.hint} to={finding.to} />)}
        {claude && <Row label='Claude' hint={route} to='/services' />}
        {outside > 0 && <Row label={`Мимо VPN: ${outside} ${plural(outside, 'устройство', 'устройства', 'устройств')} в сети`} hint='Для них карточки и kill switch не действуют.' to='/devices' />}
    </Group>
}
