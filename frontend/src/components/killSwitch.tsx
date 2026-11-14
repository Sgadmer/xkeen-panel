import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row, Switch } from '@/components/ios'
import { api } from '@/lib/api'

type Override = 'on' | 'off'
type Policy = { enabled: boolean; services: Record<string, Override> | null }
type Change = { enabled: boolean } | { service_id: string; mode: Override | 'inherit' }
const key = ['kill-switch']
const path = '/api/kill-switch'

export function useKillSwitch(enabled = true) {
    const client = useQueryClient()
    const query = useQuery({ queryKey: key, queryFn: () => api.get<Policy>(path), enabled })
    const save = useMutation({
        mutationKey: key,
        mutationFn: (change: Change) => api.put<Policy>(path, change),
        onMutate: () => client.cancelQueries({ queryKey: key }),
        onSuccess: (policy) => client.setQueryData(key, policy),
        onSettled: () => Promise.all([key, ['service-routes'], ['claude-api-firewall']].map(queryKey => client.invalidateQueries({ queryKey }))),
    })
    const busy = useIsMutating({ mutationKey: key }) > 0
    return { data: query.data, busy, save: save.mutate, error: save.error ?? query.error }
}

export function GlobalKillSwitch() {
    const policy = useKillSwitch()
    return (
        <Group title='Защита VPN' footer={policy.error
            ? <span role='alert' className='text-destructive'>{policy.error.message}</span>
            : 'Индивидуальный переключатель в карточке сервиса имеет приоритет. Прямые маршруты продолжают работать.'}>
            <Row label='Kill switch' hint={policy.data?.enabled === false
                ? 'При отказе VPN разрешён запасной прямой выход.'
                : 'Блокировать прямой выход, если выбранный VPN недоступен.'}
                trailing={policy.data
                    ? <Switch label='Общий kill switch' checked={policy.data.enabled} disabled={policy.busy}
                        onChange={enabled => policy.save({ enabled })} />
                    : <span role='status' className='text-sm text-muted-foreground'>{policy.error ? 'Нет данных' : 'Загружаем…'}</span>} />
        </Group>
    )
}

export function ServiceKillSwitch({ policy, id, name }: {
    policy: ReturnType<typeof useKillSwitch>; id: string; name: string
}) {
    if (!policy.data) return null
    const override = policy.data.services?.[id]
    const checked = override ? override === 'on' : policy.data.enabled
    return (
        <div className='mt-3 border-t border-separator pt-3 text-sm'>
            <div className='flex items-center justify-between gap-3'>
                <div>
                    <p className='font-semibold'>Kill switch</p>
                    <p className='text-muted-foreground'>{override ? 'Своё правило' : 'По общему правилу'} · {checked ? 'включён' : 'выключен'}</p>
                </div>
                <Switch label={'Kill switch · ' + name} checked={checked} disabled={policy.busy}
                    onChange={enabled => policy.save({ service_id: id, mode: enabled ? 'on' : 'off' })} />
            </div>
            <button type='button' disabled={policy.busy} className='mt-1 min-h-9 text-tint disabled:opacity-60'
                onClick={() => policy.save({ service_id: id, mode: override ? 'inherit' : (checked ? 'on' : 'off') })}>
                {override ? 'Использовать общее правило' : 'Закрепить для этого сервиса'}
            </button>
        </div>
    )
}
