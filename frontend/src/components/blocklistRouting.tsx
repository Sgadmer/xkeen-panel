import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { api } from '@/lib/api'

type GeoPolicy = {
    enabled: boolean
    mode?: 'protected' | 'blocklist' | 'custom'
    protected_fallback?: boolean
    source: string
    domains: number
    prefixes: number
    updated_at?: string
    error?: string
}

const key = ['routing-blocklist']
const path = '/api/routing/blocklist'
const count = new Intl.NumberFormat('ru-RU')

function useBlocklist(onApplied?: () => void) {
    const client = useQueryClient()
    const state = useQuery({ queryKey: key, queryFn: () => api.get<GeoPolicy>(path), refetchInterval: 60000 })
    const update = useMutation({
        mutationFn: (op: boolean | 'refresh') => op === 'refresh'
            ? api.post<GeoPolicy>(path + '/refresh')
            : api.put<GeoPolicy>(path, { enabled: op }),
        onMutate: () => client.cancelQueries({ queryKey: key }),
        onSuccess: (policy, op) => {
            client.setQueryData(key, policy)
            for (const k of ['status', 'pool', 'service-routes']) void client.invalidateQueries({ queryKey: [k] })
            if (op !== 'refresh') onApplied?.()
        },
        onError: () => { void client.invalidateQueries({ queryKey: key }) },
    })
    return { state, update }
}

// What happens to traffic no service card claims: through the VPN as well, or
// only the addresses of the block list.
export function BlocklistRouting({ onApplied }: { onApplied?: () => void }) {
    const { state, update } = useBlocklist(onApplied)
    const [confirming, setConfirming] = useState(false)
    const data = state.data
    const error = (confirming ? undefined : update.error?.message) || state.error?.message || data?.error
    const protectedMode = data?.mode === 'protected' || !data?.mode && !data?.enabled && data?.protected_fallback === true
    return <div className='flex flex-col gap-5'>
        <Group title='Неопознанный трафик' footer='Запросы, которые не относятся ни к одной карточке сервиса. Ваши исключения действуют в обоих режимах. При смене режима часть соединений переподключится.'>
            {data ? <fieldset disabled={update.isPending} className='divide-y divide-white/10' aria-label='Режим VPN'>
                <label className='flex min-h-20 cursor-pointer items-center gap-3 py-3'>
                    <input type='radio' name='routing-mode' value='protected' checked={protectedMode}
                        onClick={() => { if (protectedMode) update.mutate(false) }} onChange={() => { if (!protectedMode) update.mutate(false) }} className='size-5 shrink-0 accent-indigo-500' />
                    <span className='min-w-0 flex-1'>
                        <span className='flex flex-wrap items-center gap-x-2 gap-y-1 text-[17px]'>Защищённый режим <span className='rounded-full bg-tint/10 px-2 py-0.5 text-xs font-medium text-tint'>Рекомендуется</span></span>
                        <span className='mt-1 block text-[13px] text-muted-foreground'>Всё неопознанное идёт через основной VPN.</span>
                    </span>
                </label>
                <label className='flex min-h-20 cursor-pointer items-center gap-3 py-3'>
                    <input type='radio' name='routing-mode' value='blocklist' checked={data.mode === 'blocklist' || !data.mode && data.enabled}
                        onChange={() => { update.reset(); setConfirming(true) }} className='size-5 shrink-0 accent-indigo-500' />
                    <span className='min-w-0 flex-1'>
                        <span className='block text-[17px]'>Только по списку блокировок</span>
                        <span className='mt-1 block text-[13px] text-muted-foreground'>Через VPN идут адреса из списка Re:filter, остальное — напрямую.</span>
                    </span>
                </label>
            </fieldset> : <p role='status' className='py-4 text-sm text-muted-foreground'>{state.isPending ? 'Загружаем режим…' : 'Не удалось прочитать режим'}</p>}
            {data?.mode === 'custom' && <p role='status' className='py-3 text-[13px] text-warning'>Сейчас действуют собственные правила профиля. Выберите защищённый режим, чтобы неопознанные запросы тоже шли через VPN.</p>}
            {data?.enabled && <p role='alert' className='py-3 text-[13px] leading-relaxed text-warning'>
                Приложение может обратиться к адресу, которого ещё нет в правилах его карточки. Сейчас такой запрос уйдёт напрямую — даже при включённом kill switch карточки.
            </p>}
        </Group>
        {confirming && <ProtectionWarning title='Перейти на режим «по списку блокировок»?' confirmLabel='Перейти на режим по списку'
            busy={update.isPending} error={update.error?.message}
            onCancel={() => { setConfirming(false); update.reset() }}
            onConfirm={() => { update.mutateAsync(true).then(() => setConfirming(false), () => {}) }}>
            <p>Через VPN пойдут только адреса из списка блокировок и из карточек сервисов. Всё остальное откроется <strong className='text-foreground'>напрямую</strong>, с домашнего адреса.</p>
            <p className='rounded-xl bg-warning/10 p-3 text-warning'>Приложения обращаются и к адресам, которых ещё нет в правилах их карточки. В этом режиме такие запросы уйдут напрямую — даже при включённом kill switch карточки.</p>
        </ProtectionWarning>}
        {update.isPending && !confirming && <p role='status' className='px-4 text-sm text-tint'>Проверяем и применяем правила…</p>}
        {error && <p role='alert' className='px-4 text-sm text-destructive'>{error}</p>}
    </div>
}

const WEEK = 7 * 24 * 60 * 60 * 1000

// The block list itself: how large it is and how fresh.
export function RefilterBase() {
    const { state, update } = useBlocklist()
    const data = state.data
    const changed = data?.updated_at ? Date.parse(data.updated_at) : 0
    const days = changed ? Math.floor((Date.now() - changed) / (24 * 60 * 60 * 1000)) : 0
    const stale = changed > 0 && Date.now() - changed > WEEK
    const error = update.error?.message || state.error?.message
    return <Group title='Список блокировок Re:filter' footer={stale
        ? <span className='text-warning'>Файлы списка на роутере не менялись больше недели. Панель применяет их, но не скачивает: это делает расписание геобаз XKeen ниже. Проверьте, что оно включено.</span>
        : 'Заблокированные сайты и сервисы с региональными ограничениями. Файлы скачивает XKeen по своему расписанию; панель подхватывает их в течение минуты.'}>
        {data && (data.domains > 0 || data.prefixes > 0) ? <>
            <Row label='Сайтов и сетей' detail={`${count.format(data.domains)} · ${count.format(data.prefixes)}`} />
            {changed > 0 && <Row label='Файлы изменились' detail={<span className={stale ? 'text-warning' : undefined}>{days === 0 ? 'сегодня' : `${days} дн. назад`}</span>}
                hint={new Date(changed).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })} />}
        </> : <Row label={state.isPending ? 'Читаем список…' : 'Список пока не прочитан'} />}
        {data?.enabled && <Row label={update.isPending ? 'Перечитываем…' : 'Перечитать файлы с роутера'} tone='tint' disabled={update.isPending} onClick={() => update.mutate('refresh')} />}
        {error && <p role='alert' className='py-3 text-sm text-destructive'>{error}</p>}
    </Group>
}
