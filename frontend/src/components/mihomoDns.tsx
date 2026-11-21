import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { ApiError, api } from '@/lib/api'

type Preset = { id: string; name: string; servers: string[] }
type Dns = {
    mode: 'router' | 'secure'
    preset?: string
    servers?: string[]
    presets: Preset[]
    foreign: boolean
    foreign_servers?: string[]
}
type Wanted = { mode: 'router' | 'secure'; preset?: string; servers?: string[] }

const key = ['mihomo-dns']
const path = '/api/dns'
const CUSTOM = 'custom'
const field = 'w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none focus:border-tint disabled:opacity-50'

// Whom the core itself asks for addresses. The devices of the home network
// keep asking the router either way.
export function MihomoDns() {
    const client = useQueryClient()
    const query = useQuery({ queryKey: key, queryFn: () => api.get<Dns>(path) })
    const data = query.data
    const [secure, setSecure] = useState(false)
    const [preset, setPreset] = useState('cloudflare')
    const [own, setOwn] = useState('')
    const [confirming, setConfirming] = useState<Wanted | null>(null)
    const [notice, setNotice] = useState('')
    useEffect(() => {
        if (!data) return
        setSecure(data.mode === 'secure')
        setPreset(data.preset || 'cloudflare')
        setOwn((data.servers ?? []).join('\n'))
    }, [data])
    const save = useMutation({
        mutationFn: (wanted: Wanted) => api.put<Dns>(path, wanted),
        onSuccess: (next, wanted) => {
            client.setQueryData(key, next)
            setConfirming(null)
            setNotice(wanted.mode === 'secure' ? 'Ядро проверило новый DNS и перешло на него.' : 'Ядро снова спрашивает адреса у роутера.')
        },
        onError: error => {
            // The panel has already put the previous settings back.
            if (error instanceof ApiError) void client.invalidateQueries({ queryKey: key })
        },
    })
    if (!data) return <Group title='DNS ядра Mihomo'><Row label={query.isPending ? 'Читаем настройки…' : 'Не удалось прочитать настройки DNS'} hint={query.error?.message} /></Group>
    if (data.foreign) {
        return <Group title='DNS ядра Mihomo' footer='Эти настройки пришли вместе с профилем Mihomo. Панель их показывает, но не меняет.'>
            <Row label='Свои настройки профиля' hint={(data.foreign_servers ?? []).join(', ') || 'Серверы DNS заданы в профиле.'} />
        </Group>
    }

    const wanted: Wanted = !secure ? { mode: 'router' }
        : preset === CUSTOM ? { mode: 'secure', preset: CUSTOM, servers: own.split(/\r?\n/).map(line => line.trim()).filter(Boolean) }
            : { mode: 'secure', preset }
    const same = wanted.mode === data.mode && (wanted.mode === 'router' || wanted.preset === data.preset && (wanted.preset !== CUSTOM || (wanted.servers ?? []).join('\n') === (data.servers ?? []).join('\n')))
    const ready = !same && !save.isPending && (wanted.preset !== CUSTOM || (wanted.servers?.length ?? 0) > 0)
    const chosen = data.presets.find(item => item.id === preset)
    const apply = () => {
        save.reset()
        setNotice('')
        if (wanted.mode === 'secure') setConfirming(wanted)
        else save.mutate(wanted)
    }

    return <Group title='DNS ядра Mihomo' footer='Это DNS самого ядра: им оно находит серверы профиля и сайты, которые у него спрашивают по имени. Устройства домашней сети по-прежнему спрашивают роутер — их DNS настраивается в веб-интерфейсе роутера.'>
        <fieldset disabled={save.isPending} className='divide-y divide-white/10' aria-label='DNS ядра'>
            <label className='flex min-h-16 cursor-pointer items-center gap-3 py-3'>
                <input type='radio' name='core-dns' checked={!secure} onChange={() => setSecure(false)} className='size-5 shrink-0 accent-indigo-500' />
                <span className='min-w-0 flex-1'>
                    <span className='flex flex-wrap items-center gap-x-2 gap-y-1 text-[17px]'>Как у роутера <span className='rounded-full bg-tint/10 px-2 py-0.5 text-xs font-medium text-tint'>Рекомендуется</span></span>
                    <span className='mt-1 block text-[13px] text-muted-foreground'>Ядро спрашивает адреса у роутера, как любая программа на нём.</span>
                </span>
            </label>
            <label className='flex min-h-16 cursor-pointer items-center gap-3 py-3'>
                <input type='radio' name='core-dns' checked={secure} onChange={() => setSecure(true)} className='size-5 shrink-0 accent-indigo-500' />
                <span className='min-w-0 flex-1'>
                    <span className='block text-[17px]'>Зашифрованный DNS</span>
                    <span className='mt-1 block text-[13px] text-muted-foreground'>Ядро спрашивает выбранную службу по зашифрованному каналу, минуя DNS провайдера.</span>
                </span>
            </label>
        </fieldset>
        {secure && <div className='space-y-3 py-3'>
            <label className='block text-[13px] text-muted-foreground'>Служба
                <select aria-label='Служба DNS' value={preset} disabled={save.isPending} onChange={event => setPreset(event.target.value)} className={field + ' mt-1 min-h-11'}>
                    {data.presets.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                    <option value={CUSTOM}>Свои адреса</option>
                </select>
            </label>
            {preset === CUSTOM
                ? <label className='block text-[13px] text-muted-foreground'>Адреса, по одному в строке — до четырёх
                    <textarea aria-label='Адреса DNS' value={own} rows={3} disabled={save.isPending} spellCheck={false} autoCapitalize='none' onChange={event => setOwn(event.target.value)}
                        placeholder={'https://dns.example.org/dns-query\ntls://dns.example.org'} className={field + ' mt-1 min-h-24 resize-y font-mono text-[15px]'} />
                    <span className='mt-1 block'>Подойдут адреса https:// и tls://. Хотя бы один должен быть зашифрованным.</span>
                </label>
                : chosen && <p className='break-all text-[13px] text-muted-foreground'>{chosen.servers.join(' · ')}</p>}
        </div>}
        <Row label={save.isPending ? 'Применяем и проверяем…' : 'Применить'} tone='tint' disabled={!ready} onClick={apply} />
        {notice && <p role='status' className='py-3 text-sm text-tint'>{notice}</p>}
        {!confirming && save.error && <p role='alert' className='py-3 text-sm text-destructive'>{save.error.message}</p>}
        {confirming && <ProtectionWarning title='Перевести ядро на зашифрованный DNS?' confirmLabel='Перевести' busy={save.isPending} error={save.error?.message}
            onCancel={() => { if (!save.isPending) { setConfirming(null); save.reset() } }} onConfirm={() => save.mutate(confirming)}>
            <p>Ядро начнёт искать адреса серверов через выбранную службу. Сразу после применения панель проверит, что ядро получает ответы.</p>
            <p className='rounded-xl bg-warning/10 p-3 text-warning'>Если служба с вашего роутера недоступна, панель сама вернёт прежние настройки. Открытые соединения при этом не рвутся.</p>
        </ProtectionWarning>}
    </Group>
}
