import {
    IconArrowsExchange,
    IconBell,
    IconCpu,
    IconDownload,
    IconFingerprint,
    IconListSearch,
    IconRefresh,
    IconRestore,
    IconShieldLock,
    IconWand,
} from '@tabler/icons-react'
import { Group, IconTile, PageTitle, Row } from '@/components/ios'
import { ProtectionSummary } from '@/components/protectionSummary'
import { useAuth } from '@/hooks/useAuth'
import { usePanelSettings, useStatus, useUpdate } from '@/hooks/usePanelData'
import { intervalLabel } from '@/components/settingsSheets'
import { useSetupState } from '@/pages/welcomePage'

const icon = (color: string, Glyph: typeof IconCpu) => (
    <IconTile color={color}>
        <Glyph className='size-[17px]' stroke={2.2} />
    </IconTile>
)

// Six sections, each named for what the owner wants to do there.
export function SettingsPage() {
    const { logout } = useAuth()
    const status = useStatus().data
    const update = useUpdate().data
    const settings = usePanelSettings().data
    const setup = useSetupState().data
    const mihomo = status?.core === 'mihomo'
    const core = mihomo ? 'Mihomo' : status?.core === 'xray' ? 'Xray' : status?.core

    return (
        <>
            <PageTitle title='Настройки' />

            <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                <nav aria-label='Разделы настроек' className='flex min-w-0 flex-col gap-5'>
                    <Group>
                        <Row icon={icon('#30d158', IconShieldLock)} label='Защита' hint='Kill switch и неопознанный трафик' to='/settings/protection' />
                        <Row icon={icon('#ff9f0a', IconRefresh)} label='Подписки и автоматика'
                            hint={settings ? `Подписки обновляются: ${intervalLabel(settings.subscription_refresh_minutes)}` : 'Обновление подписок, замена сервера, страны'}
                            to='/settings/automation' />
                        <Row icon={icon('#0a84ff', IconListSearch)} label='Журнал' hint='Сколько соединений помнить и где хранить' to='/journal?settings=1' />
                        <Row icon={icon('#ff9500', IconBell)} label='Уведомления' hint='Какие события присылать на это устройство' to='/settings/notifications' />
                        <Row icon={icon('#5856d6', IconFingerprint)} label='Вход и безопасность' hint='Пароль, код, запасные коды, ключ доступа, адрес панели' to='/settings/security' />
                        <Row icon={icon('#6366f1', IconCpu)} label='Роутер и XKeen' hint={[core, status?.mode].filter(Boolean).join(' · ') || 'Компоненты, списки адресов, DNS'} to='/settings/components' />
                        <Row icon={icon('#64d2ff', IconArrowsExchange)} label='Перенос настроек' hint='Сохранить в файл или загрузить из файла' to='/settings/transfer' />
                        <Row icon={icon('#34c759', IconRestore)} label='Рекомендуемые настройки' hint='Что изменено и как вернуть' to='/settings/recommended' />
                        <Row
                            icon={icon('#8e8e93', IconDownload)}
                            label='О панели и обновление'
                            hint={status?.panel_version ? 'Версия ' + status.panel_version : undefined}
                            detail={
                                update?.locked ? (
                                    'Заблокировано'
                                ) : update?.available && update.latest ? (
                                    <span className='text-tint'>
                                        {update.latest.tag}
                                    </span>
                                ) : undefined
                            }
                            to='/settings/update'
                        />
                    </Group>
                    {setup && !setup.complete && <Group>
                        <Row icon={icon('#5856d6', IconWand)} label='Завершить настройку' hint='Мастер проведёт по оставшимся шагам.' to='/welcome' />
                    </Group>}
                </nav>
                <div className='flex min-w-0 flex-col gap-5'>
                    <ProtectionSummary />
                    <Group><Row label='Выйти' tone='destructive' onClick={logout} /></Group>
                </div>
            </div>
        </>
    )
}
