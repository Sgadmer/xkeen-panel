import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconAlertTriangle } from '@tabler/icons-react'
import { Group, PageTitle, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { useStatus } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import type { ListResponse, SettingsResponse, Status } from '@/types'

const back = { to: '/settings', label: 'Настройки' }

type ListName = 'port_proxying' | 'port_exclude' | 'ip_exclude'

const LISTS: { name: ListName; label: string; hint: string }[] = [
    {
        name: 'port_proxying',
        label: 'Порты проксирования',
        hint: 'Один порт или диапазон вида 596:599 в строке, # — комментарий. Пусто — все порты.',
    },
    {
        name: 'port_exclude',
        label: 'Порты-исключения',
        hint: 'Не используются вместе с портами проксирования — у тех приоритет.',
    },
    {
        name: 'ip_exclude',
        label: 'IP-исключения',
        hint: 'Обязательно с маской: 10.0.0.1/32, 192.168.0.0/16.',
    },
]

const fieldClass =
    'w-full rounded-xl bg-fill px-3 outline-none placeholder:text-muted-foreground'
const saveClass =
    'min-h-11 w-full cursor-pointer rounded-xl bg-primary text-[17px] font-semibold disabled:opacity-50'

function entries(text: string) {
    return text.split(/\r?\n/).map(line => line.replace(/#.*/, '').trim()).filter(Boolean)
}

function covers(entry: string, port: number) {
    const [from, to] = entry.split(':').map(Number)
    return Number.isFinite(from) && (to === undefined ? from === port : Number.isFinite(to) && from <= port && port <= to)
}

// What a list would let past the VPN. These lists act before the proxy core:
// neither the service cards nor a kill switch see such traffic.
function bypass(name: ListName, text: string): string | null {
    const list = entries(text)
    if (list.length === 0) return null
    if (name === 'port_proxying') {
        const missing = [443, 80].filter(port => !list.some(entry => covers(entry, port)))
        return missing.length ? `Через VPN пойдут только перечисленные порты. Порт ${missing.join(' и ')} в список не входит: обычные сайты и приложения откроются напрямую.` : null
    }
    if (name === 'port_exclude') {
        const hit = [443, 80].filter(port => list.some(entry => covers(entry, port)))
        return hit.length ? `Порт ${hit.join(' и ')} — это обычные сайты и приложения. Весь их трафик пойдёт напрямую.` : 'Соединения на эти порты пойдут напрямую, мимо VPN.'
    }
    return 'Соединения с этими адресами пойдут напрямую, мимо VPN.'
}

export function XkeenSettingsPage() {
    const qc = useQueryClient()
    const settings = useQuery({
        queryKey: ['xkeen-settings'],
        queryFn: () => api.get<SettingsResponse>('/api/xkeen/settings'),
    })
    const [ghProxy, setGhProxy] = useState('')
    const [needsRestart, setNeedsRestart] = useState(false)
    const status = useStatus().data

    useEffect(() => {
        const proxy = settings.data?.settings?.xkeen?.gh_proxy
        setGhProxy(typeof proxy === 'string' ? proxy : '')
    }, [settings.data])

    const save = useMutation({
        mutationFn: () => {
            const current = settings.data?.settings ?? {}
            const section = {
                ...((current.xkeen as Record<string, unknown>) ?? {}),
            }
            if (ghProxy.trim()) section.gh_proxy = ghProxy.trim()
            else delete section.gh_proxy
            const next = { ...current }
            if (Object.keys(section).length > 0) next.xkeen = section
            else delete next.xkeen
            return api.put('/api/xkeen/settings', { settings: next })
        },
        onSuccess: () => qc.invalidateQueries({ queryKey: ['xkeen-settings'] }),
    })
    const restart = useMutation({
        mutationFn: () => api.post('/api/xkeen/restart'),
        onMutate: () => qc.setQueryData<Status>(['status'], old => old ? { ...old, restarting: true } : old),
        onSuccess: () => setNeedsRestart(false),
        onSettled: () => qc.invalidateQueries({ queryKey: ['status'] }),
    })

    return (
        <>
            <PageTitle
                title='Порты и исключения'
                back={back}
            />

            <div role='note' className='flex items-start gap-3 rounded-card border border-warning/30 bg-warning/5 p-4 text-sm'>
                <IconAlertTriangle aria-hidden className='mt-0.5 size-5 shrink-0 text-warning' />
                <p>Эти списки срабатывают раньше VPN. Всё, что они пропускают, идёт напрямую: карточки сервисов и kill switch такой трафик не видят. Для отдельных сайтов используйте раздел «Исключения».</p>
            </div>

            {needsRestart && <Group footer={restart.error ? <span role='alert' className='text-destructive'>{restart.error.message}</span> : 'Списки читаются при запуске XKeen. Соединения ненадолго прервутся.'}>
                <Row label={restart.isPending || status?.restarting ? 'Перезапускаем XKeen…' : 'Перезапустить XKeen сейчас'} tone='tint'
                    disabled={restart.isPending || status?.restarting} onClick={() => restart.mutate()} />
            </Group>}

            <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                {LISTS.map(list => (
                    <ListEditor key={list.name} {...list} onSaved={() => setNeedsRestart(true)} />
                ))}

                <Group
                    title='Загрузки с GitHub'
                    footer={
                        save.error ? (
                            <span className='text-destructive'>
                                {save.error.message}
                            </span>
                        ) : save.isSuccess ? (
                            <span className='text-success'>Сохранено</span>
                        ) : (
                            'Прокси, через который XKeen скачивает обновления, когда GitHub недоступен напрямую.'
                        )
                    }
                >
                    <div className='flex flex-col gap-2 py-3'>
                        <label htmlFor='gh-proxy' className='sr-only'>
                            Прокси для GitHub
                        </label>
                        <input
                            id='gh-proxy'
                            value={ghProxy}
                            onChange={e => setGhProxy(e.target.value)}
                            placeholder='https://gh-proxy.com'
                            className={`${fieldClass} min-h-11 text-[17px]`}
                        />
                        <button
                            type='button'
                            onClick={() => save.mutate()}
                            disabled={save.isPending}
                            className={saveClass}
                        >
                            Сохранить
                        </button>
                    </div>
                </Group>
            </div>
        </>
    )
}

function ListEditor({
    name,
    label,
    hint,
    onSaved,
}: {
    name: ListName
    label: string
    hint: string
    onSaved: () => void
}) {
    const qc = useQueryClient()
    const [open, setOpen] = useState(false)
    const [text, setText] = useState('')
    const [warning, setWarning] = useState<string | null>(null)
    const list = useQuery({
        queryKey: ['xkeen-list', name],
        queryFn: () => api.get<ListResponse>(`/api/xkeen/lists/${name}`),
        enabled: open,
    })

    useEffect(() => setText(list.data?.content ?? ''), [list.data])

    const save = useMutation({
        mutationFn: () =>
            api.put(`/api/xkeen/lists/${name}`, { content: text }),
        onSuccess: () => {
            setWarning(null)
            onSaved()
            return qc.invalidateQueries({ queryKey: ['xkeen-list', name] })
        },
    })

    const submit = () => {
        save.reset()
        const risk = bypass(name, text)
        // Saving the same risky list again needs no second warning.
        if (risk && bypass(name, list.data?.content ?? '') !== risk) setWarning(risk)
        else save.mutate()
    }

    return (
        <Group
            footer={
                save.error && !warning ? (
                    <span className='text-destructive'>
                        {save.error.message}
                    </span>
                ) : save.isSuccess ? (
                    <span className='text-success'>
                        Сохранено. Изменение начнёт действовать после перезапуска XKeen.
                    </span>
                ) : (
                    hint
                )
            }
        >
            <Row
                label={label}
                detail={open ? 'Скрыть' : 'Изменить'}
                onClick={() => setOpen(v => !v)}
            />
            {open && (
                <div className='flex flex-col gap-2 py-3'>
                    <label htmlFor={`list-${name}`} className='sr-only'>
                        {label}
                    </label>
                    <textarea
                        id={`list-${name}`}
                        value={text}
                        onChange={e => setText(e.target.value)}
                        spellCheck={false}
                        rows={8}
                        className={`${fieldClass} py-2 font-mono text-[13px]`}
                    />
                    <button
                        type='button'
                        onClick={submit}
                        disabled={save.isPending || list.isLoading}
                        className={saveClass}
                    >
                        Сохранить
                    </button>
                </div>
            )}
            {warning && <ProtectionWarning title={`${label}: трафик пойдёт мимо VPN`} confirmLabel='Сохранить список'
                busy={save.isPending} error={save.error?.message}
                onCancel={() => { setWarning(null); save.reset() }}
                onConfirm={() => save.mutate()}>
                <p>{warning}</p>
                <p className='text-muted-foreground'>Карточки сервисов и kill switch на такой трафик не действуют: он не доходит до VPN.</p>
            </ProtectionWarning>}
        </Group>
    )
}
