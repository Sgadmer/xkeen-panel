import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconAlertTriangle } from '@tabler/icons-react'
import { Group, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { useXkeenRestart, type XkeenRestart } from '@/hooks/useXkeenRestart'
import { api } from '@/lib/api'
import { plural } from '@/lib/format'
import type { ListResponse } from '@/types'

type ListName = 'port_proxying' | 'port_exclude' | 'ip_exclude'
// A saved list waits for an XKeen restart; after it the list is in force.
type Stage = 'saved' | 'applied'

// port_proxying turns the rule around: only the named ports reach the VPN.
// It is a usual way to spare the router, as long as 80 and 443 stay in it.
const LISTS: { name: ListName; label: string; about: string; hint: string }[] = [
    {
        name: 'port_proxying',
        label: 'Только эти порты через VPN',
        about: 'Через VPN идёт только то, что идёт на эти порты. Всё остальное идёт напрямую, мимо VPN, и меньше нагружает роутер. Обычно это игры и торренты, но напрямую могут пойти и звонки в мессенджерах. Пусто — через VPN идут все порты.',
        hint: 'По одному в строке: 443 или диапазон 596:599. Порты 80 и 443 обязательны: это обычные сайты и приложения. 596:599 — звонки Telegram. Пока список заполнен, «Порты в обход VPN» не действуют.',
    },
    {
        name: 'port_exclude',
        label: 'Порты в обход VPN',
        about: 'Всё, что идёт на эти порты, уходит напрямую — к любому сайту и с любого устройства. Например, порт торрент-клиента.',
        hint: 'По одному в строке: 27015 или диапазон 27000:27100. Строка, которая начинается с #, не действует.',
    },
    {
        name: 'ip_exclude',
        label: 'Адреса в обход VPN',
        about: 'Соединения с этими адресами уходят напрямую. Например, сервер рабочего VPN.',
        hint: 'Один адрес пишите с /32 на конце: 203.0.113.5/32. Сеть — как есть: 203.0.113.0/24.',
    },
]

const fieldClass =
    'w-full rounded-xl bg-fill px-3 outline-none placeholder:text-muted-foreground'
const saveClass =
    'min-h-11 w-full cursor-pointer rounded-xl bg-primary text-[17px] font-semibold disabled:opacity-50'

const records = (n: number) => `${n} ${plural(n, 'запись', 'записи', 'записей')}`

function entries(text: string) {
    return text.split(/\r?\n/).map(line => line.replace(/#.*/, '').trim()).filter(Boolean)
}

function covers(entry: string, port: number) {
    const [from, to] = entry.split(':').map(Number)
    return Number.isFinite(from) && (to === undefined ? from === port : Number.isFinite(to) && from <= port && port <= to)
}

// The web ports a filled port_proxying list leaves out: without them ordinary
// sites and applications go past the VPN.
function missingWeb(list: string[]) {
    return list.length ? [443, 80].filter(port => !list.some(entry => covers(entry, port))) : []
}

// What a list would let past the VPN.
function bypass(name: ListName, text: string): string | null {
    const list = entries(text)
    if (list.length === 0) return null
    if (name === 'port_exclude') {
        const hit = [443, 80].filter(port => list.some(entry => covers(entry, port)))
        return hit.length ? `Порт ${hit.join(' и ')} — это обычные сайты и приложения. Весь их трафик пойдёт напрямую.` : 'Соединения на эти порты пойдут напрямую, мимо VPN.'
    }
    return 'Соединения с этими адресами пойдут напрямую, мимо VPN.'
}

// The warning a save needs, if any. Saving the same risky list again needs
// none, and neither does a port added to port_proxying: more goes to the VPN.
function risk(name: ListName, saved: string, text: string): string | null {
    if (name !== 'port_proxying') {
        const now = bypass(name, text)
        return now && bypass(name, saved) !== now ? now : null
    }
    const now = entries(text), was = entries(saved)
    if (now.length === 0 || was.length > 0 && was.every(entry => now.includes(entry))) return null
    return `Через VPN пойдут только порты: ${now.join(', ')}. Всё остальное — например, игры, торренты и звонки — пойдёт напрямую.`
}

function useList(name: ListName) {
    return useQuery({
        queryKey: ['xkeen-list', name],
        queryFn: () => api.get<ListResponse>(`/api/xkeen/lists/${name}`),
    })
}

// The lists of XKeen itself. They act on the router before the proxy core:
// what they let through reaches neither the journal, nor the service cards,
// nor a kill switch. Rarely needed, so the block stays folded.
export function RouterBypass() {
    const [open, setOpen] = useState(false)
    const [stage, setStage] = useState<Partial<Record<ListName, Stage>>>({})
    const ports = useList('port_exclude')
    const addresses = useList('ip_exclude')
    const only = useList('port_proxying')
    const restart = useXkeenRestart()

    // One restart puts every saved list in force.
    useEffect(() => {
        if (restart.done) setStage(old => {
            const next = { ...old }
            for (const name of Object.keys(next) as ListName[]) if (next[name] === 'saved') next[name] = 'applied'
            return next
        })
    }, [restart.done])
    const waiting = Object.values(stage).includes('saved')

    const allowed = entries(only.data?.content ?? '')
    const count = entries(ports.data?.content ?? '').length + entries(addresses.data?.content ?? '').length
    const failed = ports.error ?? addresses.error ?? only.error
    const state = failed ? <span className='text-destructive'>Списки не загружены: {failed.message}</span>
        : !(ports.data && addresses.data && only.data) ? null
        : missingWeb(allowed).length ? <span className='text-destructive'>Сейчас сайты и приложения идут мимо VPN: в списке портов нет {missingWeb(allowed).join(' и ')}.</span>
        : allowed.length ? <>Сейчас через VPN идут только порты {allowed.join(', ')}; остальное — напрямую.</>
        : count ? <span className='text-warning'>Сейчас в обход VPN: {records(count)}.</span>
        : 'Сейчас пусто.'
    const saved = (name: ListName) => {
        restart.reset()
        setStage(old => ({ ...old, [name]: 'saved' }))
    }

    return (
        <section aria-label='Полный обход VPN' className='flex min-w-0 flex-col gap-5'>
            <Group title='Для редких случаев'>
                <Row
                    label='Полный обход VPN'
                    hint={<>Нужно редко: для игр, торрентов, звонков или рабочего VPN, если они тормозят или не работают.{state && <span className='mt-1 block'>{state}</span>}
                        {waiting && <span className='mt-1 block text-warning'>Сохранённые изменения начнут действовать после перезапуска XKeen.</span>}</>}
                    detail={open ? 'Скрыть' : 'Открыть'}
                    onClick={() => setOpen(v => !v)}
                />
            </Group>

            {open && <>
                <div role='note' className='flex items-start gap-3 rounded-card border border-warning/30 bg-warning/5 p-4 text-sm'>
                    <IconAlertTriangle aria-hidden className='mt-0.5 size-5 shrink-0 text-warning' />
                    <div className='space-y-2'>
                        <p>Всё, что указано здесь, роутер отправляет к провайдеру сразу, в обход VPN. Это быстрее, но панель такой трафик не видит и не защищает: его нет в журнале, карточки сервисов и kill switch на него не действуют. Чтобы открыть напрямую один сайт, добавьте его в список выше.</p>
                        <p className='text-muted-foreground'>Порт — это номер, по которому программа выходит в интернет. Сайты и обычные приложения используют 80 и 443. У игр и торрентов свои номера, они написаны в настройках программы.</p>
                    </div>
                </div>

                <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                    {LISTS.map(list => <ListEditor key={list.name} {...list} stage={stage[list.name]} restart={restart} onSaved={() => saved(list.name)} />)}
                </div>
            </>}
        </section>
    )
}

function ListEditor({
    name,
    label,
    about,
    hint,
    stage,
    restart,
    onSaved,
}: {
    name: ListName
    label: string
    about: string
    hint: string
    stage?: Stage
    restart: XkeenRestart
    onSaved: () => void
}) {
    const qc = useQueryClient()
    const [open, setOpen] = useState(false)
    const [text, setText] = useState('')
    const [warning, setWarning] = useState<string | null>(null)
    const list = useList(name)

    useEffect(() => setText(list.data?.content ?? ''), [list.data])

    const save = useMutation({
        mutationFn: () =>
            api.put(`/api/xkeen/lists/${name}`, { content: text }),
        onSuccess: () => {
            setWarning(null)
            onSaved()
            qc.setQueryData<ListResponse>(['xkeen-list', name], old => old ? { ...old, content: text } : old)
            return qc.invalidateQueries({ queryKey: ['xkeen-list', name] })
        },
    })

    // The server's refusals come before the warning, not after its five seconds.
    const check = useMutation({
        mutationFn: () => api.put(`/api/xkeen/lists/${name}`, { content: text, check: true }),
    })

    const submit = () => {
        save.reset()
        check.reset()
        const danger = risk(name, list.data?.content ?? '', text)
        if (danger) check.mutate(undefined, { onSuccess: () => setWarning(danger) })
        else save.mutate()
    }

    const current = entries(list.data?.content ?? '')
    const count = current.length
    // A list written by hand or by an older panel may lack the web ports.
    const broken = name === 'port_proxying' ? missingWeb(current) : []
    const error = check.error ?? (warning ? null : save.error)
    // The saved text is on screen: the next step is the restart, right here.
    const untouched = !!list.data && text === (list.data.content ?? '')
    const awaiting = stage === 'saved' && untouched

    return (
        <Group
            title={label}
            footer={
                error ? (
                    <span role='alert' className='text-destructive'>
                        {error.message}
                    </span>
                ) : awaiting ? (
                    restart.result ?? <span className='text-success'>
                        Сохранено. Чтобы список начал действовать, перезапустите XKeen: интернет на устройствах прервётся на несколько секунд.
                    </span>
                ) : stage === 'applied' && untouched ? (
                    <span role='status' className='text-success'>
                        XKeen перезапущен. Список действует.
                    </span>
                ) : (
                    hint
                )
            }
        >
            <Row
                label={list.data ? (count ? (name === 'port_proxying' ? current.join(', ') : records(count)) : 'Пусто') : 'Загрузка…'}
                hint={broken.length
                    ? <><span className='block text-destructive'>В списке нет порта {broken.join(' и ')}: обычные сайты и приложения сейчас идут мимо VPN. Добавьте его или очистите список.</span>{about}</>
                    : about}
                detail={open ? 'Скрыть' : 'Изменить'}
                onClick={() => setOpen(v => !v)}
            />
            {(open || awaiting) && (
                <div className='flex flex-col gap-2 py-3'>
                    {open && <>
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
                    </>}
                    {awaiting ? (
                        <button type='button' onClick={restart.click} disabled={restart.busy} className={saveClass}>
                            {restart.label}
                        </button>
                    ) : (
                        <button
                            type='button'
                            onClick={submit}
                            disabled={save.isPending || check.isPending || list.isLoading}
                            className={saveClass}
                        >
                            Сохранить
                        </button>
                    )}
                </div>
            )}
            {warning && <ProtectionWarning title={name === 'port_proxying' ? 'Через VPN пойдут только выбранные порты' : `${label}: трафик пойдёт мимо VPN`} confirmLabel='Сохранить список'
                busy={save.isPending} error={save.error?.message}
                onCancel={() => { setWarning(null); save.reset() }}
                onConfirm={() => save.mutate()}>
                <p>{warning}</p>
                <p className='text-muted-foreground'>Карточки сервисов и kill switch на такой трафик не действуют: он не доходит до VPN.</p>
            </ProtectionWarning>}
        </Group>
    )
}
