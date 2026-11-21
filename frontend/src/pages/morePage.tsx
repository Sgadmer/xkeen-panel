import { Group, PageTitle, Row } from '@/components/ios'
import { MORE_SECTIONS } from '@/components/appShell'

const hints: Record<string, string> = {
    '/devices': 'Кому из домашних устройств нужен VPN',
    '/exclusions': 'Адреса, которые открываются напрямую',
    '/diagnostics': 'Проверки, нагрузка роутера, перезапуск',
    '/settings': 'Защита, подписки, вход, обновления',
}

// The sections that do not fit into the bar of a phone.
export function MorePage() {
    return <>
        <PageTitle title='Ещё' />
        <Group>
            {MORE_SECTIONS.map(section => {
                const Icon = section.icon
                return <Row key={section.to} to={section.to} label={section.label} hint={hints[section.to]}
                    icon={<Icon aria-hidden className='size-6 shrink-0 text-tint' stroke={1.8} />} />
            })}
        </Group>
    </>
}
