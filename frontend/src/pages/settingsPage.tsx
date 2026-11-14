import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
    IconBell,
    IconActivity,
    IconAdjustmentsHorizontal,
    IconArrowsExchange,
    IconCpu,
    IconDownload,
    IconFingerprint,
    IconWand,
} from '@tabler/icons-react'
import { Group, IconTile, PageTitle, Row } from '@/components/ios'
import { GlobalKillSwitch } from '@/components/killSwitch'
import { useAuth } from '@/hooks/useAuth'
import { useStatus, useUpdate } from '@/hooks/usePanelData'
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

    return (
        <>
            <PageTitle title='Настройки' />

            <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                <Group title='XKeen'>
                    <Row icon={icon('#0a84ff', IconArrowsExchange)} label='Режим VPN и сервисы' hint={status?.core === 'mihomo' ? 'По списку блокировок или по правилам профиля' : 'Выбранные сервисы или весь трафик'} to='/settings/routing' />
                    <Row icon={icon('#6366f1', IconCpu)} label='Компоненты и геобазы' hint='Версии XKeen/Xray, обновления и геоданные' to='/settings/components' />
                    <Row
                        icon={icon('#30d158', IconArrowsExchange)}
                        label='Исключения VPN'
                        hint='Домены, URL, IP-адреса и подсети без VPN'
                        to='/exclusions'
                    />
                    <Row
                        icon={icon('#6366f1', IconCpu)}
                        label='Ядро'
                        detail={
                            status
                                ? `${status.core === 'mihomo' ? 'Mihomo' : 'Xray'} · ${status.mode}`
                                : '—'
                        }
                    />
                    <Row
                        icon={icon('#0a84ff', IconAdjustmentsHorizontal)}
                        label='Порты и системные исключения'
                        detail={status?.xkeen_version}
                        to='/settings/xkeen'
                    />
                </Group>

                <Group
                    title='Панель'
                    footer={
                        addPasskey.error ? (
                            <span className='text-destructive'>
                                {addPasskey.error.message}
                            </span>
                        ) : (
                            'Face ID и Touch ID работают только при входе через HTTPS-домен роутера.'
                        )
                    }
                >
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
                            ) : (
                                status?.panel_version
                            )
                        }
                        to='/settings/update'
                    />
                    {passkey ? (
                        <Row
                            icon={icon('#30d158', IconFingerprint)}
                            label='Вход по Face ID'
                            hint={`ключ ${passkey.slice(0, 8)}…`}
                            trailing={
                                <button
                                    type='button'
                                    onClick={() =>
                                        removePasskey.mutate(passkey)
                                    }
                                    disabled={removePasskey.isPending}
                                    className='min-h-9 cursor-pointer px-1 text-[15px] text-destructive'
                                >
                                    Удалить
                                </button>
                            }
                        />
                    ) : !passkeySupported() ? (
                        <Row icon={icon('#30d158', IconFingerprint)} label='Настроить Face ID на iPhone'
                            hint='Получить HTTPS-адрес панели для Safari' to='/settings/access#face-id' />
                    ) : (
                        <Row
                            icon={icon('#30d158', IconFingerprint)}
                            label={
                                addPasskey.isPending
                                    ? 'Создаю ключ…'
                                    : 'Включить вход по Face ID'
                            }
                            tone='tint'
                            onClick={() => addPasskey.mutate()}
                            disabled={
                                !passkeySupported() || addPasskey.isPending
                            }
                        />
                    )}
                    <Row
                        icon={icon('#5856d6', IconWand)}
                        label='Мастер настройки'
                        to='/welcome'
                    />
                    <Row
                        icon={icon('#ff375f', IconActivity)}
                        label='Диагностика и журнал'
                        to='/diagnostics'
                    />
                </Group>

                {status?.core === 'mihomo' && <div id='kill-switch'><GlobalKillSwitch /></div>}
                <Group>
                    <Row label='Выйти' tone='destructive' onClick={logout} />
                </Group>
            </div>
        </>
    )
}
