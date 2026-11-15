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
    updated_at?: string
    checked_at?: string
    next_check_at?: string
    error?: string
    shared_dependencies: string
}

const path = '/api/routing/service-lists'
const key = ['service-lists']
const count = new Intl.NumberFormat('ru-RU')

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
    return <Group title='Распознавание сервисов' footer='Списки помогают узнать сервис по адресу сайта. Общие адреса сбора аналитики и ошибок используют карточку «Аналитика и диагностика». Серверы покупок и входа, например RevenueCat и WorkOS, используют маршрут ChatGPT. Произвольный запрос без имени сайта роутер не может достоверно связать с приложением.'>
        <Row label='Обновляемые списки сервисов' hint='Новые адреса скачиваются автоматически раз в сутки при любом режиме VPN. Выбранные серверы сохраняются. При ошибке продолжает работать прежняя база.'
            detail={data ? (busy ? 'Проверяем…' : 'Автоматически') : state.isPending ? 'Загружаем…' : 'Нет данных'} />
        {data && <>
            <Row label='Имена сайтов в соединениях' hint='Роутер распознаёт имя сайта при подключении. QUIC на портах 443 и 8443 блокируется: приложения обычно переходят на HTTPS, чтобы запрос не попал в чужой маршрут.' detail={data.ready === false ? 'Ожидаем базу' : 'Включено'} />
            <Row label='База адресов' detail={`Списков: ${count.format(data.sources)} · правил: ${count.format(data.domains)}`} />
            {data.source && <Row label='Источник' detail={data.source} />}
            {data.checked_at && <Row label='Последняя проверка' detail={new Date(data.checked_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })} />}
            {data.next_check_at && <Row label='Следующая проверка' detail={new Date(data.next_check_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })} />}
            <button type='button' disabled={busy} onClick={() => update.mutate()} className='min-h-11 cursor-pointer py-2 text-tint disabled:opacity-60'>Проверить обновление списков</button>
        </>}
        {busy && <p role='status' className='py-3 text-sm text-tint'>Загружаем и проверяем списки. VPN продолжает работать с прежними правилами…</p>}
        {error && <p role='alert' className='py-3 text-sm text-destructive'>{safeNotice(error, 'Не удалось обновить правила. Прежняя рабочая база сохранена.')}</p>}
    </Group>
}
