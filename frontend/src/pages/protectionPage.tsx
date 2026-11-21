import { Group, PageTitle, Row } from '@/components/ios'
import { GlobalKillSwitch } from '@/components/killSwitch'
import { ProtectionSummary } from '@/components/protectionSummary'
import { useStatus } from '@/hooks/usePanelData'
import { RoutingModeForm } from '@/pages/routingModePage'

// Everything that decides whether traffic may leave past the VPN, in one place.
export function ProtectionPage() {
    const status = useStatus().data
    const mihomo = status?.core === 'mihomo'
    return <>
        <PageTitle title='Защита' subtitle='Что происходит, когда VPN недоступен или адрес не опознан' back={{ to: '/settings', label: 'Настройки' }} />
        <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
            <div className='flex min-w-0 flex-col gap-5'>
                <ProtectionSummary />
                {mihomo && <GlobalKillSwitch />}
                <Group footer='Kill switch отдельной карточки и её маршрут меняются в самой карточке.'>
                    <Row label='Карточки сервисов' hint='Маршрут и kill switch каждого сервиса' to='/services' />
                    <Row label='Устройства' hint='Кому из домашних устройств нужен VPN' to='/devices' />
                    <Row label='Исключения' hint='Адреса, которые открываются напрямую' to='/exclusions' />
                </Group>
            </div>
            <div className='flex min-w-0 flex-col gap-5'>
                <RoutingModeForm />
            </div>
        </div>
    </>
}
