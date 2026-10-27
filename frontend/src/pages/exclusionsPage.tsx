import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconLoader2, IconPlus, IconRouteOff, IconTrash } from '@tabler/icons-react'
import { Group, PageTitle, Row } from '@/components/ios'
import { api } from '@/lib/api'

interface ExclusionEntry {
    id: string
    type: 'domain' | 'full' | 'ip'
    value: string
    comment: string
}

interface Exclusions {
    entries: ExclusionEntry[]
}

const typeLabels: Record<ExclusionEntry['type'], string> = {
    domain: 'Домен и поддомены',
    full: 'Точный домен',
    ip: 'IP / подсеть',
}

const inputClass =
    'mt-1.5 min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none transition-colors focus:border-tint disabled:opacity-50'

export function ExclusionsPage() {
    const qc = useQueryClient()
    const [value, setValue] = useState('')
    const [comment, setComment] = useState('')
    const [notice, setNotice] = useState('')
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
        onSuccess: data => {
            applied(data, 'Исключение добавлено и применено.')
            setValue('')
            setComment('')
        },
    })
    const remove = useMutation({
        mutationFn: (id: string) =>
            api.del<Exclusions>(`/api/exclusions/${encodeURIComponent(id)}`),
        onSuccess: data => applied(data, 'Исключение удалено и изменения применены.'),
    })

    const busy = add.isPending || remove.isPending
    const entries = query.data?.entries ?? []
    const error = add.error ?? remove.error

    function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault()
        if (busy || !value.trim()) return
        setNotice('')
        remove.reset()
        add.mutate({ value: value.trim(), comment: comment.trim() })
    }

    function deleteEntry(entry: ExclusionEntry) {
        setNotice('')
        add.reset()
        remove.mutate(entry.id)
    }

    return (
        <>
            <PageTitle
                title='Исключения VPN'
                subtitle='Указанные адреса открываются напрямую через провайдера.'
            />

            <Group
                title='Добавить исключение'
                footer='Домен включает все его поддомены. Из URL используется только адрес сайта: путь, порт и параметры не ограничивают исключение. Для одного конкретного домена используйте full:host.example.com.'
            >
                <form onSubmit={submit} className='flex flex-col gap-4 py-4'>
                    <label className='text-[15px] font-medium' htmlFor='exclusion-value'>
                        URL, домен, IP-адрес или подсеть
                        <input
                            id='exclusion-value'
                            name='value'
                            type='text'
                            value={value}
                            onChange={event => setValue(event.target.value)}
                            placeholder='lenta.com или 192.0.2.0/24'
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
                    <p className='text-[13px] leading-snug text-muted-foreground'>
                        Изменения применяются сразу. VPN может ненадолго прерваться
                        при перезапуске. Исключения сохраняются при смене сервера и
                        обновлении подписки.
                    </p>
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

            <Group
                title={`Ваши исключения${query.data ? ` · ${entries.length}` : ''}`}
                footer='Здесь показаны исключения, добавленные вручную. Системные правила маршрутизации продолжают действовать.'
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
                        <div key={entry.id} className='flex min-w-0 items-center gap-3 py-3'>
                            <div className='min-w-0 flex-1'>
                                <p className='break-all text-[16px] font-medium'>{entry.value}</p>
                                {entry.comment && (
                                    <p className='mt-0.5 break-words text-[13px] text-muted-foreground'>
                                        {entry.comment}
                                    </p>
                                )}
                                <span className='mt-1.5 inline-block rounded-full bg-fill px-2 py-0.5 text-[11px] text-muted-foreground'>
                                    {typeLabels[entry.type] ?? entry.type}
                                </span>
                            </div>
                            <button
                                type='button'
                                aria-label={`Удалить исключение ${entry.value}`}
                                title='Удалить исключение'
                                disabled={busy}
                                onClick={() => deleteEntry(entry)}
                                className='flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-xl text-destructive hover:bg-white/6 disabled:cursor-default disabled:opacity-50'
                            >
                                {remove.isPending && remove.variables === entry.id ? (
                                    <IconLoader2 className='size-5 animate-spin' />
                                ) : (
                                    <IconTrash className='size-5' />
                                )}
                            </button>
                        </div>
                    ))
                )}
            </Group>
        </>
    )
}
