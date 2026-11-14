import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row, Switch } from '@/components/ios'
import { api } from '@/lib/api'

type GeoPolicy = {
    enabled: boolean
    source: string
    domains: number
    prefixes: number
    updated_at?: string
    error?: string
}

const key = ['routing-blocklist']
const path = '/api/routing/blocklist'
const count = new Intl.NumberFormat('ru-RU')

export function BlocklistRouting({ onApplied }: { onApplied?: () => void }) {
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
    const data = state.data
    const error = update.error?.message || state.error?.message || data?.error
    return <div className='flex flex-col gap-5'>
        <Group title='Маршруты Mihomo' footer='При смене режима открытые соединения могут переподключиться по новым правилам. Выключение возвращает прежний порядок правил профиля.'>
            <Row label='VPN по списку блокировок' hint='Для сервиса с автовыбором или ручным маршрутом действует его карточка. Для остальных сайтов роутер сверяет адрес со списком Re:filter. Адреса из списка открываются через основной VPN, остальные — напрямую.'
                trailing={data ? <Switch label='VPN по списку блокировок' checked={data.enabled} disabled={update.isPending}
                    onChange={enabled => update.mutate(enabled)} /> : <span role='status' className='text-sm text-muted-foreground'>{state.isPending ? 'Загружаем…' : 'Нет данных'}</span>} />
        </Group>
        <Group title='Геобазы' footer='GeoSite проверяет имя сайта. GeoIP проверяет IP, когда имя определить не удалось. Это сохраняет прямой выход для обычных сайтов на общем IP с заблокированным сервисом.'>
            <Row label='Re:filter' hint='Список включает блокировки и сервисы с региональными ограничениями. Панель раз в минуту проверяет файлы на роутере и применяет новые правила. Свежие файлы должен скачивать XKeen или другой загрузчик.' />
            {data && (data.domains > 0 || data.prefixes > 0) && <>
                <Row label='Доменные правила' detail={count.format(data.domains)} />
                <Row label='IP-префиксы' detail={count.format(data.prefixes)} />
                {data.updated_at && <Row label='Последнее изменение правил' detail={new Date(data.updated_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })} />}
            </>}
            {data?.enabled && <button type='button' className='min-h-11 py-2 text-tint disabled:opacity-60' disabled={update.isPending}
                onClick={() => update.mutate('refresh')}>Перечитать геобазы роутера</button>}
        </Group>
        {update.isPending && <p role='status' className='px-4 text-sm text-tint'>Проверяем и применяем правила…</p>}
        {error && <p role='alert' className='px-4 text-sm text-destructive'>{error}</p>}
    </div>
}
