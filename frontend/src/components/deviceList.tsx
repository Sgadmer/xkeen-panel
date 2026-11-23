import { useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
    IconDeviceDesktop,
    IconDeviceLaptop,
    IconDeviceMobile,
    IconDeviceTv,
    IconDeviceWatch,
    IconHome,
    IconPencil,
    IconSearch,
    type Icon,
} from '@tabler/icons-react'
import { Group, IconTile, Row, Switch } from '@/components/ios'
import { DeviceEditor } from '@/components/deviceEditor'
import { ProtectionWarning } from '@/components/protectionWarning'
import { api } from '@/lib/api'
import { plural } from '@/lib/format'
import type { Device, DevicesResponse } from '@/types'

// The icon is guessed from the name the device gave itself. Smart-home gear
// comes before TV boxes: «Hue Sync Box» is a lamp controller, not a TV.
const KINDS: { re: RegExp; icon: Icon; color: string }[] = [
    { re: /watch|часы/i, icon: IconDeviceWatch, color: '#8e8e93' },
    {
        re: /iphone|phone|телефон|фон|android|pixel|galaxy|poco|oneplus|redmi|xiaomi|samsung|\bs2\d|honor|huawei|realme|vivo|oppo|nokia|motorola/i,
        icon: IconDeviceMobile,
        color: '#30d158',
    },
    {
        re: /macbook|book|laptop|ноут/i,
        icon: IconDeviceLaptop,
        color: '#0a84ff',
    },
    {
        re: /хаб|hub|hue|bridge|sync|станц|lamp|ламп|розетк|датчик|esp-|tuya|yeelight|aqara/i,
        icon: IconHome,
        color: '#ff9f0a',
    },
    {
        re: /\btv|tv\b|телевиз|ящик|box|приставк/i,
        icon: IconDeviceTv,
        color: '#6366f1',
    },
]

const OFFLINE_KEY = 'xkeen.devices.offline.v1'

function offlineShown() {
    try {
        return localStorage.getItem(OFFLINE_KEY) === '1'
    } catch {
        return false
    }
}

function kindOf(name: string) {
    return (
        KINDS.find(k => k.re.test(name)) ?? {
            icon: IconDeviceDesktop,
            color: '#64d2ff',
        }
    )
}

export function DeviceGroups({
    data,
    columns,
    showConnections = false,
    manage = false,
}: {
    data: DevicesResponse
    columns?: boolean
    showConnections?: boolean
    manage?: boolean
}) {
    const qc = useQueryClient()
    const [editing, setEditing] = useState<Device | null>(null)
    const [leaving, setLeaving] = useState<Device | null>(null)
    const [notice, setNotice] = useState('')
    const [query, setQuery] = useState('')
    const [showOffline, setShowOffline] = useState(offlineShown)
    const toggleOffline = () => setShowOffline(open => {
        try { localStorage.setItem(OFFLINE_KEY, open ? '0' : '1') } catch { /* until the page is closed */ }
        return !open
    })
    const opener = useRef<HTMLButtonElement>(null)
    const groups = useRef<HTMLDivElement>(null)
    const toggle = useMutation({
        mutationFn: ({ mac, vpn }: { mac: string; vpn: boolean }) =>
            api.post('/api/devices/vpn', { mac, vpn }),
        onMutate: ({ mac, vpn }) =>
            qc.setQueryData<DevicesResponse>(['devices'], old =>
                old
                    ? {
                          ...old,
                          devices: old.devices.map(d =>
                              d.mac === mac
                                  ? { ...d, vpn, via: vpn ? 'host' : undefined }
                                  : d,
                          ),
                      }
                    : old,
            ),
        onSettled: () => qc.invalidateQueries({ queryKey: ['devices'] }),
    })

    const row = (d: Device) => {
        const kind = kindOf(d.name)
        const KindIcon = kind.icon
        const route = d.vpn ? (d.via === 'segment' ? 'Через VPN, как вся сеть' : 'Через VPN') : 'Напрямую'
        return (
            <Row
                key={d.mac}
                icon={
                    <span className={d.active ? '' : 'opacity-45'}>
                        <IconTile color={kind.color}>
                            <KindIcon className='size-[17px]' stroke={2.2} />
                        </IconTile>
                    </span>
                }
                label={manage ? <button type='button' aria-haspopup='dialog'
                    aria-label={'Изменить устройство ' + d.name}
                    className='group inline-flex max-w-full cursor-pointer items-baseline gap-1.5 rounded text-left hover:text-tint focus-visible:outline-2 focus-visible:outline-tint'
                    onClick={event => { opener.current = event.currentTarget; setNotice(''); setEditing(d) }}>
                    <span className='min-w-0 [overflow-wrap:anywhere]'>{d.name}</span>
                    <IconPencil aria-hidden className='size-4 shrink-0 self-center text-muted-foreground group-hover:text-tint' />
                </button> : <span className='block break-words'>{d.name}</span>}
                hint={<>
                    {route}
                    {showConnections && d.mac && <>{' · '}
                        <Link className='inline-block py-1 text-tint hover:underline'
                            to={'/journal?device=' + encodeURIComponent('mac:' + d.mac.toLowerCase())}
                            aria-label={'Журнал устройства ' + d.name}>Журнал</Link>
                    </>}
                </>}
                trailing={
                    <Switch
                        checked={d.vpn}
                        onChange={vpn => {
                            toggle.reset()
                            // Taking a device out of the VPN lowers protection: ask first.
                            if (vpn) toggle.mutate({ mac: d.mac, vpn })
                            else setLeaving(d)
                        }}
                        label={`VPN для ${d.name}`}
                        disabled={!data.policy_found || toggle.isPending}
                    />
                }
            />
        )
    }

    const wanted = query.trim().toLowerCase()
    const shown = wanted ? data.devices.filter(d => d.name.toLowerCase().includes(wanted) || d.mac.toLowerCase().includes(wanted)) : data.devices
    const online = shown.filter(d => d.active)
    const offline = shown.filter(d => !d.active)
    // A long tail of devices that are away stays folded until it is asked for.
    const foldable = manage && !wanted && offline.length > 5
    const offlineOpen = !foldable || showOffline

    return (
        <>
            {manage && data.devices.length > 8 && <label className='flex min-h-11 items-center gap-2 rounded-xl bg-fill px-3 lg:max-w-sm'>
                <IconSearch aria-hidden className='size-4 shrink-0 text-muted-foreground' stroke={2.2} />
                <span className='sr-only'>Найти устройство</span>
                <input type='search' value={query} onChange={event => setQuery(event.target.value)} placeholder='Найти устройство'
                    className='min-w-0 flex-1 bg-transparent text-[16px] outline-none placeholder:text-muted-foreground' />
            </label>}
            {wanted && shown.length === 0 && <p className='px-4 text-sm text-muted-foreground'>Такого устройства нет в списке.</p>}
            {notice && <p role='status' className='px-4 text-sm text-muted-foreground'>{notice}</p>}
            {toggle.error && (
                <p className='px-4 text-[13px] text-destructive'>
                    {toggle.error.message}
                </p>
            )}
            <div
                ref={groups}
                tabIndex={-1}
                className={
                    columns
                        ? 'grid grid-cols-1 gap-4 lg:grid-cols-2 lg:items-start'
                        : 'flex flex-col gap-4'
                }
            >
                {online.length > 0 && (
                    <Group title='В сети'>{online.map(row)}</Group>
                )}
                {offline.length > 0 && (
                    <Group title={foldable ? <button type='button' aria-expanded={offlineOpen} onClick={toggleOffline}
                        className='flex w-full cursor-pointer items-center justify-between gap-2 uppercase'>
                        <span>Не в сети · {offline.length}</span>
                        <span className='normal-case text-tint'>{offlineOpen ? 'Свернуть' : 'Показать'}</span>
                    </button> : 'Не в сети'}>
                        {offlineOpen ? offline.map(row) : <Row label={`${offline.length} ${plural(offline.length, 'устройство', 'устройства', 'устройств')}`}
                            hint={`Через VPN: ${offline.filter(d => d.vpn).length}`} onClick={toggleOffline} />}
                    </Group>
                )}
            </div>
            {leaving && <ProtectionWarning key={leaving.mac} title='Отключить VPN для устройства?' confirmLabel='Пустить напрямую'
                busy={toggle.isPending}
                onCancel={() => setLeaving(null)}
                onConfirm={() => { toggle.mutate({ mac: leaving.mac, vpn: false }); setLeaving(null) }}>
                <p>Устройство <strong className='text-foreground'>{leaving.name}</strong> будет выходить в интернет напрямую, с домашнего адреса. Роутер перестанет направлять его трафик в VPN, поэтому карточки сервисов и kill switch на него действовать не будут.</p>
                <p className='text-muted-foreground'>Claude, ChatGPT и другие сервисы на этом устройстве увидят ваш настоящий адрес.</p>
            </ProtectionWarning>}
            {editing && <DeviceEditor key={editing.mac}
                device={data.devices.find(d => d.mac === editing.mac) ?? editing}
                returnFocus={() => opener.current?.isConnected ? opener.current : groups.current}
                onClose={() => setEditing(null)}
                onSaved={message => { setNotice(message); setEditing(null) }} />}
        </>
    )
}

export function NewDevicesGroup({ data }: { data: DevicesResponse }) {
    const qc = useQueryClient()
    // Devices following the segment flip with it, so the list is refetched rather than patched
    const newDevices = useMutation({
        mutationFn: (vpn: boolean) => api.post('/api/devices/new', { vpn }),
        onMutate: vpn =>
            qc.setQueryData<DevicesResponse>(['devices'], old =>
                old ? { ...old, new_devices_vpn: vpn } : old,
            ),
        onSettled: () => qc.invalidateQueries({ queryKey: ['devices'] }),
    })

    const [confirming, setConfirming] = useState(false)
    return (
        <Group
            footer={
                newDevices.error ? (
                    <span className='text-destructive'>
                        {newDevices.error.message}
                    </span>
                ) : (
                    'Всё, что впервые подключится к домашней сети, и устройства, у которых в Keenetic выбрана политика сегмента («как вся сеть»).'
                )
            }
        >
            <Row
                label='Новые устройства через VPN'
                trailing={
                    <Switch
                        checked={data.new_devices_vpn}
                        onChange={vpn => {
                            newDevices.reset()
                            if (vpn) newDevices.mutate(vpn)
                            else setConfirming(true)
                        }}
                        label='Новые устройства через VPN'
                        disabled={newDevices.isPending}
                    />
                }
            />
            {confirming && <ProtectionWarning title='Новые устройства — напрямую?' confirmLabel='Пускать напрямую'
                onCancel={() => setConfirming(false)}
                onConfirm={() => { newDevices.mutate(false); setConfirming(false) }}>
                <p>Каждое устройство, которое впервые подключится к домашней сети, будет выходить в интернет <strong className='text-foreground'>напрямую</strong>, пока вы не включите для него VPN вручную.</p>
                <p className='text-muted-foreground'>То же произойдёт с устройствами, которые сейчас идут «как вся сеть».</p>
            </ProtectionWarning>}
        </Group>
    )
}
