import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconLoader2, IconPencil, IconPlus, IconRouteOff, IconShieldExclamation, IconTrash } from '@tabler/icons-react'
import { Group, PageTitle, Row, Switch } from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { useStatus } from '@/hooks/usePanelData'
import { api } from '@/lib/api'

interface ExclusionEntry {
    id: string
    type: 'domain' | 'full' | 'ip' | 'pattern'
    value: string
    comment: string
    disabled?: boolean
}

interface Exclusions {
    entries: ExclusionEntry[]
    // Entry id -> the protected service card whose addresses it overlaps.
    covered?: Record<string, string>
}

const typeLabels: Record<ExclusionEntry['type'], string> = {
    domain: 'Домен и поддомены',
    full: 'Только этот адрес',
    ip: 'IP / подсеть',
    pattern: 'Шаблон',
}

// The stored value carries its kind as a prefix; the list shows the address
// and names the kind next to it.
const shown = (entry: ExclusionEntry) => entry.value.replace(/^(domain|full|pattern):/, '')
// In the edit field an exact address keeps its prefix, or saving would widen
// it to the whole domain.
const editable = (entry: ExclusionEntry) => entry.type === 'full' ? entry.value : shown(entry)

const inputClass =
    'mt-1.5 min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none transition-colors focus:border-tint disabled:opacity-50'

export function ExclusionsPage() {
    const mihomo = useStatus().data?.core === 'mihomo'
    const qc = useQueryClient()
    const [value, setValue] = useState('')
    const [comment, setComment] = useState('')
    const [notice, setNotice] = useState('')
    const [removed, setRemoved] = useState<ExclusionEntry | null>(null)
    const [editing, setEditing] = useState<ExclusionEntry | null>(null)
    const [draft, setDraft] = useState({ value: '', comment: '' })
    const query = useQuery({
        queryKey: ['exclusions'],
        queryFn: () => api.get<Exclusions>('/api/exclusions'),
    })

    function applied(data: Exclusions, message: string) {
        qc.setQueryData(['exclusions'], data)
        qc.invalidateQueries({ queryKey: ['status'] })
        qc.invalidateQueries({ queryKey: ['pool'] })
        setNotice(message)
    }

    const add = useMutation({
        mutationFn: (entry: { value: string; comment: string }) =>
            api.post<Exclusions>('/api/exclusions', entry),
        onSuccess: (data, entry) => {
            applied(data, 'Исключение добавлено и применено.')
            if (entry.value === value.trim()) {
                setValue('')
                setComment('')
            }
        },
    })
    const remove = useMutation({
        mutationFn: (entry: ExclusionEntry) =>
            api.del<Exclusions>(`/api/exclusions/${encodeURIComponent(entry.id)}`),
        onSuccess: (data, entry) => {
            applied(data, '')
            setRemoved(entry)
        },
    })
    const change = useMutation({
        mutationFn: ({ id, ...patch }: { id: string; value?: string; comment?: string; disabled?: boolean }) =>
            api.put<Exclusions>(`/api/exclusions/${encodeURIComponent(id)}`, patch),
        onSuccess: (data, patch) => {
            applied(data, patch.disabled === undefined ? 'Исключение изменено.' : patch.disabled ? 'Исключение выключено: адрес идёт по общим правилам.' : 'Исключение включено.')
            setEditing(null)
        },
    })

    // "Вернуть" stays for a few seconds after a removal.
    useEffect(() => {
        if (!removed) return
        const timer = window.setTimeout(() => setRemoved(null), 8000)
        return () => window.clearTimeout(timer)
    }, [removed])

    const busy = add.isPending || remove.isPending || change.isPending
    const entries = query.data?.entries ?? []
    const covered = query.data?.covered ?? {}
    const error = add.error ?? remove.error ?? (editing ? null : change.error)

    function reset() {
        setNotice('')
        add.reset()
        remove.reset()
        change.reset()
    }

    function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault()
        if (busy || !value.trim()) return
        reset()
        setRemoved(null)
        add.mutate({ value: value.trim(), comment: comment.trim() })
    }

    function restore() {
        if (!removed || busy) return
        const entry = removed
        reset()
        setRemoved(null)
        add.mutate({ value: entry.value, comment: entry.comment })
    }

    function edit(entry: ExclusionEntry) {
        reset()
        setDraft({ value: editable(entry), comment: entry.comment })
        setEditing(entry)
    }

    function saveEdit() {
        if (!editing || busy || !draft.value.trim()) return
        change.mutate({ id: editing.id, value: draft.value.trim(), comment: draft.comment.trim() })
    }

    return (
        <>
            <PageTitle
                title='Исключения VPN'
                subtitle='Указанные адреса открываются напрямую через провайдера.'
            />

            <Group
                title='Добавить исключение'
                footer={<>Домен включает все его поддомены. Звёздочка заменяет любую часть имени: <span className='whitespace-nowrap'>www.example.*</span> или <span className='whitespace-nowrap'>*.cdn.example.com</span>. Только один адрес — <span className='whitespace-nowrap'>full:host.example.com</span>.</>}
            >
                <form onSubmit={submit} className='flex flex-col gap-4 py-4'>
                    <label className='text-[15px] font-medium' htmlFor='exclusion-value'>
                        Домен, шаблон, ссылка, IP-адрес или подсеть
                        <input
                            id='exclusion-value'
                            name='value'
                            type='text'
                            value={value}
                            onChange={event => setValue(event.target.value)}
                            placeholder='lenta.com, www.example.* или 192.0.2.0/24'
                            autoCapitalize='none'
                            autoComplete='off'
                            spellCheck={false}
                            maxLength={2048}
                            required
                            disabled={busy || !query.data}
                            className={inputClass}
                        />
                    </label>
                    <label className='text-[15px] font-medium' htmlFor='exclusion-comment'>
                        Комментарий <span className='font-normal text-muted-foreground'>(необязательно)</span>
                        <input
                            id='exclusion-comment'
                            name='comment'
                            type='text'
                            value={comment}
                            onChange={event => setComment(event.target.value)}
                            placeholder='Например, приложение «Лента»'
                            maxLength={200}
                            disabled={busy || !query.data}
                            className={inputClass}
                        />
                    </label>
                    <button
                        type='submit'
                        disabled={busy || !query.data || !value.trim()}
                        className='flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl bg-primary px-4 text-[15px] font-semibold text-primary-foreground disabled:cursor-default disabled:opacity-50'
                    >
                        {add.isPending ? (
                            <IconLoader2 className='size-5 animate-spin' />
                        ) : (
                            <IconPlus className='size-5' />
                        )}
                        {add.isPending ? 'Применение…' : 'Добавить исключение'}
                    </button>
                    {!mihomo && <p className='text-[13px] leading-snug text-muted-foreground'>
                        При перезапуске VPN соединения могут ненадолго прерваться.
                    </p>}
                </form>
            </Group>

            {error && (
                <p role='alert' className='px-4 text-[15px] text-destructive'>
                    {error.message}
                </p>
            )}
            <div role='status' aria-live='polite' className='px-4 text-[15px] text-tint empty:hidden'>
                {busy ? 'Применяем изменения, дождитесь завершения…' : notice}
            </div>
            {removed && !busy && (
                <div role='status' className='flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-card bg-card px-4 py-2 text-[15px]'>
                    <span className='min-w-0 break-all'>Удалено: {shown(removed)}</span>
                    <button type='button' onClick={restore} className='min-h-11 cursor-pointer font-semibold text-tint'>Вернуть</button>
                </div>
            )}

            <Group
                title={`Ваши исключения${query.data ? ` · ${entries.length}` : ''}`}
                footer={mihomo ? 'Адреса из карточек сервисов сюда добавить нельзя, пока у карточки включён kill switch: их маршрут выбирается в самой карточке.' : undefined}
            >
                {query.isPending ? (
                    <Row
                        label='Загрузка исключений…'
                        trailing={<IconLoader2 className='size-5 animate-spin text-muted-foreground' />}
                    />
                ) : query.error ? (
                    <>
                        <Row label='Не удалось загрузить исключения' hint={query.error.message} tone='destructive' />
                        <Row label='Повторить' tone='tint' onClick={() => query.refetch()} disabled={query.isFetching} />
                    </>
                ) : entries.length === 0 ? (
                    <Row
                        icon={<IconRouteOff className='size-6 shrink-0 text-muted-foreground' />}
                        label='Пока нет исключений'
                        hint='Добавьте адрес выше, чтобы открывать его без VPN.'
                    />
                ) : (
                    entries.map(entry => (
                        <div key={entry.id} className='flex min-w-0 items-center gap-2 py-3'>
                            <div className={'min-w-0 flex-1' + (entry.disabled ? ' opacity-55' : '')}>
                                <p className='break-all text-[16px] font-medium'>{shown(entry)}</p>
                                {entry.comment && (
                                    <p className='mt-0.5 break-words text-[13px] text-muted-foreground'>
                                        {entry.comment}
                                    </p>
                                )}
                                <span className='mt-1.5 inline-block rounded-full bg-fill px-2 py-0.5 text-[11px] text-muted-foreground'>
                                    {typeLabels[entry.type] ?? entry.type}{entry.disabled ? ' · выключено' : ''}
                                </span>
                                {covered[entry.id] && (
                                    <p className='mt-1.5 flex items-start gap-1.5 text-[13px] text-warning'>
                                        <IconShieldExclamation aria-hidden className='mt-px size-4 shrink-0' />
                                        Пересекается с карточкой «{covered[entry.id]}», у которой включён kill switch.
                                    </p>
                                )}
                            </div>
                            {mihomo && <>
                                <button
                                    type='button'
                                    aria-label={`Изменить исключение ${shown(entry)}`}
                                    title='Изменить'
                                    disabled={busy}
                                    onClick={() => edit(entry)}
                                    className='flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-xl text-muted-foreground hover:bg-white/6 disabled:cursor-default disabled:opacity-50'
                                >
                                    <IconPencil className='size-5' />
                                </button>
                                <Switch
                                    checked={!entry.disabled}
                                    label={`Исключение ${shown(entry)}`}
                                    disabled={busy}
                                    onChange={enabled => { reset(); setRemoved(null); change.mutate({ id: entry.id, disabled: !enabled }) }}
                                />
                            </>}
                            <button
                                type='button'
                                aria-label={`Удалить исключение ${shown(entry)}`}
                                title='Удалить исключение'
                                disabled={busy}
                                onClick={() => { reset(); setRemoved(null); remove.mutate(entry) }}
                                className='flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-xl text-destructive hover:bg-white/6 disabled:cursor-default disabled:opacity-50'
                            >
                                {remove.isPending && remove.variables?.id === entry.id ? (
                                    <IconLoader2 className='size-5 animate-spin' />
                                ) : (
                                    <IconTrash className='size-5' />
                                )}
                            </button>
                        </div>
                    ))
                )}
            </Group>

            <Sheet
                open={editing !== null}
                onClose={() => { if (!change.isPending) { setEditing(null); change.reset() } }}
                title='Изменить исключение'
                done={{ label: change.isPending ? 'Сохраняем…' : 'Сохранить', onClick: saveEdit, disabled: change.isPending || !draft.value.trim() }}
            >
                <Group footer={change.error ? <span role='alert' className='text-destructive'>{change.error.message}</span> : undefined}>
                    <label className='block py-3 text-[15px] font-medium' htmlFor='exclusion-edit-value'>
                        Адрес
                        <input
                            id='exclusion-edit-value'
                            type='text'
                            value={draft.value}
                            onChange={event => setDraft(old => ({ ...old, value: event.target.value }))}
                            autoCapitalize='none'
                            autoComplete='off'
                            spellCheck={false}
                            maxLength={2048}
                            disabled={change.isPending}
                            className={inputClass}
                        />
                    </label>
                    <label className='block py-3 text-[15px] font-medium' htmlFor='exclusion-edit-comment'>
                        Комментарий
                        <input
                            id='exclusion-edit-comment'
                            type='text'
                            value={draft.comment}
                            onChange={event => setDraft(old => ({ ...old, comment: event.target.value }))}
                            maxLength={200}
                            disabled={change.isPending}
                            className={inputClass}
                        />
                    </label>
                </Group>
            </Sheet>
        </>
    )
}
