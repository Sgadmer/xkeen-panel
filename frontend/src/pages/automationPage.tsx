import { Group, PageTitle, Row } from '@/components/ios'
import { ServerAutomation } from '@/components/serverAutomation'
import { useServerSources } from '@/hooks/usePanelData'

// What the panel does on its own: refreshes subscriptions, replaces a server
// that stopped answering, and which countries it never picks.
export function AutomationPage() {
    const sources = useServerSources().data
    return <>
        <PageTitle title='Подписки и автоматика' back={{ to: '/settings', label: 'Настройки' }} />
        <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
            <div className='flex min-w-0 flex-col gap-5'><ServerAutomation /></div>
            <Group footer='Добавить подписку, заменить ссылку или удалить источник можно в разделе «Серверы».'>
                <Row label='Подписки и источники' detail={sources ? String(sources.length) : undefined} to='/servers?sources=1' />
                <Row label='Автовыбор и размер пула' hint='Сколько серверов сравнивать и из каких стран' to='/servers' />
            </Group>
        </div>
    </>
}
