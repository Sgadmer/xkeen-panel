import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
    IconBell,
    IconAdjustmentsHorizontal,
    IconArrowsExchange,
    IconCpu,
    IconDownload,
    IconFingerprint,
    IconWand,
} from '@tabler/icons-react'
import { Group, IconTile, PageTitle, Row, Switch } from '@/components/ios'
import { GlobalKillSwitch } from '@/components/killSwitch'
import { useAuth } from '@/hooks/useAuth'
import { usePanelSettings, useStatus, useUpdate } from '@/hooks/usePanelData'
import type { PanelSettings } from '@/types'
import { api } from '@/lib/api'
import { passkeySupported, registerPasskey } from '@/lib/webauthn'

const icon = (color: string, Glyph: typeof IconCpu) => (
    <IconTile color={color}>
        <Glyph className='size-[17px]' stroke={2.2} />
    </IconTile>
)

export function SettingsPage() {
    const qc = useQueryClient()
    const { logout } = useAuth()
    const status = useStatus().data
    const update = useUpdate().data
    const settings = usePanelSettings()
    const appearance = useMutation({
        mutationFn: (show_full_path: boolean) => api.put<PanelSettings>('/api/panel/settings/appearance', { show_full_path }),
        onSuccess: data => qc.setQueryData(['panel-settings'], data),
    })

    const passkeys = useQuery({
        queryKey: ['passkeys'],
        queryFn: () => api.get<{ passkeys: string[] }>('/api/account/passkey'),
    })
    const addPasskey = useMutation({
        mutationFn: () => registerPasskey(),
        onSettled: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    })
    const removePasskey = useMutation({
        mutationFn: (id: string) => api.del('/api/account/passkey', { id }),
        onSettled: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    })
    const passkey = passkeys.data?.passkeys?.[0]
    const faceIdSetupLink = passkeys.isSuccess && !passkey && !passkeySupported()
    const passkeyError = addPasskey.error || removePasskey.error || passkeys.error
    const core = status?.core === 'mihomo' ? 'Mihomo' : status?.core === 'xray' ? 'Xray' : status?.core

    return (
        <>
            <PageTitle title='Настройки' />

            <nav aria-label='Разделы настроек' className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                <Group title='XKeen'>
                    <Row icon={icon('#0a84ff', IconArrowsExchange)} label='Режим VPN и сервисы' hint={status?.core === 'mihomo' ? 'По списку блокировок или по правилам профиля' : 'Выбранные сервисы или весь трафик'} to='/settings/routing' />
                    <Row icon={icon('#6366f1', IconCpu)} label='Компоненты и геобазы' hint={status?.core === 'mihomo' ? 'Установленные компоненты и базы Re:filter' : 'Версии XKeen/Xray, обновления и геоданные'} to='/settings/components' />
                    <Row
                        icon={icon('#0a84ff', IconAdjustmentsHorizontal)}
                        label='Порты и системные исключения'
                        to='/settings/xkeen'
                    />
                </Group>

                <Group title='Панель'>
                    <Row icon={icon('#ff9500', IconBell)} label='Уведомления' hint='Системные уведомления на этом устройстве' to='/settings/notifications' />
                    <Row icon={icon('#0a84ff', IconWand)} label='Вход с ПК и телефона' hint='HTTPS-адрес панели, QR-код и Face ID на iPhone' to='/settings/access' />
                    <Row
                        icon={icon('#8e8e93', IconDownload)}
                        label='Обновление панели'
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
                    {faceIdSetupLink && <Row icon={icon('#30d158', IconFingerprint)} label='Настроить Face ID на iPhone'
                        hint='Получить HTTPS-адрес панели для Safari' to='/settings/access#face-id' />}
                    <Row icon={icon('#5856d6', IconWand)} label='Мастер настройки' to='/welcome' />
                </Group>
            </nav>

            <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                <div className='flex min-w-0 flex-col gap-5'>
                    <Group title='Вид панели' footer={appearance.error && <span role='alert' className='text-destructive'>{appearance.error.message}</span>}>
                        <Row label='Показывать полный путь VPN'
                            hint='Показывать страны входа и выхода. Если выключить, останется только выход.'
                            trailing={<Switch label='Показывать полный путь VPN' checked={settings.data?.show_full_path !== false}
                                disabled={!settings.data || appearance.isPending} onChange={value => appearance.mutate(value)} />} />
                    </Group>
                    <Group title='Сведения'>
                        <dl className='grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 py-3 text-sm'>
                            <dt className='text-muted-foreground'>Ядро</dt><dd>{[core, status?.mode].filter(Boolean).join(' · ') || '—'}</dd>
                            <dt className='text-muted-foreground'>Версия XKeen</dt><dd>{status?.xkeen_version || '—'}</dd>
                            <dt className='text-muted-foreground'>Версия панели</dt><dd className='break-words'>{status?.panel_version || '—'}</dd>
                        </dl>
                    </Group>
                    {status?.core === 'mihomo' && <div id='kill-switch'><GlobalKillSwitch /></div>}
                </div>
                <div className='flex min-w-0 flex-col gap-5'>
                    {!faceIdSetupLink && (
                        <Group title='Вход по Face ID' footer={passkeyError && <span role='alert' className='text-destructive'>{passkeyError.message}</span>}>
                            {passkey ? (
                                <Row icon={icon('#30d158', IconFingerprint)} label='Ключ доступа'
                                    hint={`${passkey.slice(0, 8)}…`}
                                    trailing={<button type='button' onClick={() => removePasskey.mutate(passkey)}
                                        disabled={removePasskey.isPending}
                                        className='min-h-9 cursor-pointer px-1 text-[15px] text-destructive'>Удалить</button>}
                                />
                            ) : passkeys.isSuccess ? (
                                <Row icon={icon('#30d158', IconFingerprint)} tone='tint'
                                    label={addPasskey.isPending ? 'Создаю ключ…' : 'Включить вход по Face ID'}
                                    onClick={() => addPasskey.mutate()} disabled={addPasskey.isPending} />
                            ) : passkeys.isPending ? <Row label='Загружаем ключи…' /> : null}
                        </Group>
                    )}
                    <Group><Row label='Выйти' tone='destructive' onClick={logout} /></Group>
                </div>
            </div>
        </>
    )
}
