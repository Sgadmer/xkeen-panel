import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row } from '@/components/ios'
import { api } from '@/lib/api'
import { safeNotice } from '@/lib/subscription'

interface ServiceListsStatus {
    enabled: boolean
    ready?: boolean
    updating: boolean
    source: string
    sources: number
    domains: number
    voice_prefixes?: number
    updated_at?: string
    checked_at?: string
    next_check_at?: string
    error?: string
    shared_dependencies: string
}

const path = '/api/routing/service-lists'
const key = ['service-lists']
const count = new Intl.NumberFormat('ru-RU')
const stamp = (value: string) => new Date(value).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })

// The address lists by which the router tells which card a request belongs to.
export function ServiceListsProtection() {
    const client = useQueryClient()
    const state = useQuery({ queryKey: key, queryFn: () => api.get<ServiceListsStatus>(path), refetchInterval: query => query.state.data?.updating ? 2000 : 60000 })
    const update = useMutation({
        mutationFn: () => api.post<ServiceListsStatus>(path + '/refresh'),
        onSuccess: result => {
            client.setQueryData(key, result)
            for (const k of ['service-routes', 'diagnostics', 'kill-switch', 'status']) void client.invalidateQueries({ queryKey: [k] })
        },
        onError: () => { void client.invalidateQueries({ queryKey: key }) },
    })
    const data = state.data
    const busy = update.isPending || data?.updating === true
    const error = update.error?.message || state.error?.message || data?.error
    return <Group title='Списки адресов сервисов' footer='По ним роутер узнаёт, к какой карточке относится запрос. Обновляются сами раз в сутки; при ошибке работает прежняя база.'>
        {data ? <>
            <Row label='База адресов' detail={`${count.format(data.sources)} списков · ${count.format(data.domains + (data.voice_prefixes || 0))} правил`}
                hint={data.source || undefined} />
            <Row label='Имена сайтов в соединениях' hint='QUIC блокируется, чтобы роутер видел имя сайта и не отправил запрос в чужой маршрут.' detail={data.ready === false ? 'Ждём базу' : 'Видны'} />
            {data.checked_at && <Row label='Проверено' detail={stamp(data.checked_at)} hint={data.next_check_at ? 'Следующая проверка · ' + stamp(data.next_check_at) : undefined} />}
            <Row label={busy ? 'Проверяем списки…' : 'Проверить обновление сейчас'} tone='tint' disabled={busy} onClick={() => update.mutate()} />
        </> : <Row label={state.isPending ? 'Загружаем…' : 'Нет данных'} />}
        {error && <p role='alert' className='py-3 text-sm text-destructive'>{safeNotice(error, 'Не удалось обновить правила. Прежняя рабочая база сохранена.')}</p>}
    </Group>
}
