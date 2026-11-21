import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row, Switch } from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { api } from '@/lib/api'
import { safeNotice } from '@/lib/subscription'
import { formatHistoryBytes, historySettingsKey, historySettingsPath, type HistorySettings } from '@/lib/trafficHistory'

type Draft = {
    enabled: boolean
    storage_id: string
    path: string
    max_events: string
    max_device_events: string
    max_mib: string
}
const emptyDraft: Draft = { enabled: false, storage_id: '', path: '', max_events: '200000', max_device_events: '50000', max_mib: '256' }
const counts = new Intl.NumberFormat('ru-RU')
const field = 'min-h-11 min-w-0 w-full rounded-xl bg-fill px-3 text-foreground outline-none focus:ring-1 focus:ring-tint disabled:opacity-60'

function fromSettings(data: HistorySettings): Draft {
    return {
        enabled: data.enabled,
        storage_id: data.storage_id || '',
        path: data.path || '',
        max_events: String(data.max_events || 200000),
        max_device_events: String(data.max_device_events || 50000),
        max_mib: String((data.max_bytes || 256 * 1024 ** 2) / 1024 ** 2),
    }
}

export function TrafficHistorySettings({ open, onClose }: { open: boolean; onClose: () => void }) {
    const client = useQueryClient()
    const [draft, setDraft] = useState<Draft>(emptyDraft)
    const [dirty, setDirty] = useState(false)
    const [validation, setValidation] = useState('')
    const state = useQuery({
        queryKey: historySettingsKey, queryFn: () => api.get<HistorySettings>(historySettingsPath),
        enabled: open, refetchInterval: open ? 15000 : false,
    })
    useEffect(() => {
        if (open && !dirty && state.data) setDraft(fromSettings(state.data))
    }, [open, dirty, state.data])
    useEffect(() => {
        if (!open) { setDirty(false); setValidation('') }
    }, [open])
    const save = useMutation({
        mutationFn: (body: { enabled: boolean; storage_id: string; path: string; max_events: number; max_device_events: number; max_bytes: number }) => api.put<HistorySettings>(historySettingsPath, body),
        onSuccess: data => {
            client.setQueryData(historySettingsKey, data)
            void client.invalidateQueries({ queryKey: ['traffic-history'] })
            setDraft(fromSettings(data))
            setDirty(false)
            setValidation('')
        },
    })
    const data = state.data
    const supported = data?.supported !== false
    const storages = data?.storages ?? []
    const storage = storages.find(item => item.id === draft.storage_id)
    const change = (patch: Partial<Draft>) => {
        setDraft(value => ({ ...value, ...patch }))
        setDirty(true)
        setValidation('')
        save.reset()
    }
    const submit = (event: FormEvent) => {
        event.preventDefault()
        const maxEvents = Number(draft.max_events), perDevice = Number(draft.max_device_events), maxMiB = Number(draft.max_mib)
        if (draft.enabled && !supported) {
            setValidation(data?.error || 'Суточная история недоступна на этой модели роутера.')
            return
        }
        if (![maxEvents, perDevice, maxMiB, maxMiB * 1024 ** 2].every(value => Number.isSafeInteger(value) && value > 0)) {
            setValidation('Укажите положительные целые числа в ограничениях журнала.')
            return
        }
        if (perDevice > maxEvents) { setValidation('Лимит одного устройства не может превышать общий лимит.'); return }
        if (draft.enabled && (!storage?.available || !draft.path.trim())) {
            setValidation('Выберите доступный внешний диск и папку для журнала.')
            return
        }
        save.mutate({ enabled: draft.enabled, storage_id: draft.storage_id, path: draft.path.trim(), max_events: maxEvents, max_device_events: perDevice, max_bytes: maxMiB * 1024 ** 2 })
    }
    const recent = useMutation({
        mutationFn: (patch: { recent_off?: boolean; recent_events?: number }) => api.put<HistorySettings>(historySettingsPath, patch),
        onSuccess: next => {
            client.setQueryData(historySettingsKey, next)
            void client.invalidateQueries({ queryKey: ['journal'] })
        },
    })
    const recentSizes = [1000, 2000, 5000, 10000, 20000]
    const error = validation || save.error?.message || state.error?.message || (supported ? data?.error : undefined)
    return <Sheet open={open} onClose={onClose} title='Настройки журнала'>
        <form onSubmit={submit} className='flex min-w-0 flex-col gap-5'>
            <Group title='Недавние соединения' footer={recent.error
                ? <span role='alert' className='text-destructive'>{recent.error.message}</span>
                : `Хранятся в памяти роутера, диск не нужен. Закрытое соединение остаётся в журнале до ${data?.recent_minutes ?? 60} минут. После перезапуска панели журнал начинается заново.`}>
                <Row label='Помнить недавние соединения'
                    trailing={<Switch label='Помнить недавние соединения' checked={data?.recent_enabled !== false} disabled={!data || recent.isPending}
                        onChange={on => recent.mutate({ recent_off: !on })} />} />
                {data?.recent_enabled !== false && <>
                    <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Сколько записей помнить
                        <select value={data?.recent_events ?? 5000} disabled={!data || recent.isPending} className={field}
                            onChange={e => recent.mutate({ recent_events: Number(e.target.value) })}>
                            {[...new Set([...recentSizes, data?.recent_events ?? 5000])].sort((a, b) => a - b).map(size => <option key={size} value={size}>{counts.format(size)}{size === 5000 ? ' · рекомендуется' : ''}</option>)}
                        </select>
                    </label>
                    <Row label='Сейчас в журнале' detail={counts.format(data?.recent_count ?? 0)} />
                </>}
            </Group>
            {!supported && <p role='alert' className='px-3 text-sm text-warning'>{safeNotice(data?.error || '', 'Суточная история недоступна на этой модели роутера. Текущие соединения и события защиты доступны без записи на диск.')}</p>}
            <Group title='Журнал за сутки' footer='Нужен внешний диск. Изменения применятся после сохранения.'>
                <Row label='Сохранять журнал на диск' hint='Записи за последние 24 часа, переживают перезапуск.'
                    trailing={<Switch label='Сохранять историю на диск' checked={draft.enabled} disabled={!data || save.isPending || !supported && !draft.enabled} onChange={enabled => change({ enabled })} />} />
            </Group>
            <Group title='Внешний диск' footer='Выберите накопитель и папку до включения записи. При смене папки откроется отдельная история; прежние файлы сохранятся на старом месте.'>
                <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Накопитель
                    <select value={draft.storage_id} disabled={!data || save.isPending} onChange={e => {
                        const next = storages.find(item => item.id === e.target.value)
                        change({ storage_id: e.target.value, path: next?.suggested_path || '' })
                    }} className={field}>
                        <option value=''>Выберите внешний диск</option>
                        {storages.map(item => <option key={item.id} value={item.id} disabled={!item.available}>{item.label} · {item.available ? formatHistoryBytes(item.free_bytes) + ' свободно' : item.reason || 'Недоступен'}</option>)}
                    </select>
                </label>
                <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Папка журнала
                    <input type='text' value={draft.path} onChange={e => change({ path: e.target.value })} disabled={!draft.storage_id || save.isPending}
                        autoCapitalize='none' spellCheck={false} placeholder='Сначала выберите диск' className={field} />
                </label>
                {storage && <Row label='Свободно на диске' detail={formatHistoryBytes(storage.free_bytes)} hint={storage.reason} />}
                {data && !storages.some(item => item.available) && <p role='status' className='py-3 text-sm text-warning'>Доступный внешний диск не найден. Подключите накопитель и откройте настройки снова.</p>}
            </Group>
            <Group title='Ограничения' footer='Каждая запись хранится не дольше 24 часов. Если лимит количества или размера закончится раньше, самые старые записи удалятся. Поэтому фактическая история может быть короче суток.'>
                <Row label='Максимальный возраст записи' detail='24 часа' />
                <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Всего записей
                    <input type='number' min='1' step='1' inputMode='numeric' value={draft.max_events} disabled={save.isPending} onChange={e => change({ max_events: e.target.value })} className={field} />
                </label>
                <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Записей на одно устройство
                    <input type='number' min='1' step='1' inputMode='numeric' value={draft.max_device_events} disabled={save.isPending} onChange={e => change({ max_device_events: e.target.value })} className={field} />
                </label>
                <label className='grid gap-1 py-3 text-sm text-muted-foreground'>Место на диске, МиБ
                    <input type='number' min='1' step='1' inputMode='numeric' value={draft.max_mib} disabled={save.isPending} onChange={e => change({ max_mib: e.target.value })} className={field} />
                </label>
            </Group>
            {data && <Group title='Состояние журнала' footer='Если диск недоступен или очередь переполнена, часть записей может быть пропущена. Ошибка журнала не меняет маршруты VPN.'>
                <Row label='Запись' detail={data.enabled ? data.running ? 'Работает' : 'Приостановлена' : 'Выключена'} />
                <Row label='Записей в истории' detail={counts.format(data.events || 0)} />
                <Row label='Занято на диске' detail={formatHistoryBytes(data.bytes)} />
                <Row label='Ожидают записи' detail={counts.format(data.queued || 0)} />
                <Row label='Пропущено записей' detail={counts.format(data.dropped || 0)} />
                {data.oldest_at && Date.parse(data.oldest_at) > 0 && <Row label='История доступна с' detail={new Date(data.oldest_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })} />}
                {data.memory_available_bytes != null && <Row label='Свободная память роутера' detail={formatHistoryBytes(data.memory_available_bytes)} />}
            </Group>}
            {error && <p role='alert' className='px-3 text-sm text-destructive'>{safeNotice(error, 'Не удалось применить настройки истории.')}</p>}
            {save.isSuccess && !dirty && <p role='status' className='px-3 text-sm text-tint'>Настройки истории сохранены.</p>}
            <button type='submit' disabled={!data || save.isPending || !dirty || !supported && draft.enabled} className='min-h-12 cursor-pointer rounded-xl bg-primary px-4 font-semibold text-primary-foreground disabled:opacity-50'>{save.isPending ? 'Сохраняем…' : 'Сохранить настройки'}</button>
        </form>
    </Sheet>
}
