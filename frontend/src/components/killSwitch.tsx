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
            : 'В карточке каждого сервиса можно выбрать своё правило. Прямые маршруты продолжают работать.'}>
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
    return (
        <label className='mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-separator pt-2 text-sm'>
            <span className='font-medium'>Kill switch</span>
            <select aria-label={'Kill switch · ' + name} value={policy.data.services?.[id] ?? 'inherit'} disabled={policy.busy}
                className='min-h-10 max-w-full cursor-pointer rounded-lg bg-fill px-2 text-sm text-foreground disabled:opacity-60'
                onChange={event => {
                    const mode = event.target.value
                    if (mode === 'inherit' || mode === 'on' || mode === 'off') policy.save({ service_id: id, mode })
                }}>
                <option value='inherit'>Как в настройках · {policy.data.enabled ? 'вкл.' : 'выкл.'}</option>
                <option value='on'>Всегда включён</option>
                <option value='off'>Всегда выключен</option>
            </select>
        </label>
    )
}
