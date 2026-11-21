import { useState } from 'react'
import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group, Row, Switch } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { isAiService } from '@/lib/aiServiceGroup'
import { api } from '@/lib/api'

type ServiceMode = 'on' | 'off' | 'inherit'
type Policy = { enabled: boolean; services: Record<string, ServiceMode> | null }
type Change = { enabled: boolean } | { service_id: string; mode: ServiceMode }
const key = ['kill-switch']
const path = '/api/kill-switch'

export function serviceKillSwitch(policy: Policy, id: string) {
    const mode = policy.services?.[id] ?? 'on'
    return { mode, enabled: mode === 'inherit' ? policy.enabled : mode === 'on' }
}

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
    return { data: query.data, busy, save: save.mutate, saveAsync: save.mutateAsync, reset: save.reset, error: save.error ?? query.error }
}

export function GlobalKillSwitch() {
    const policy = useKillSwitch()
    const [confirming, setConfirming] = useState(false)
    return (
        <Group title='Защита VPN' footer={policy.error && !confirming
            ? <span role='alert' className='text-destructive'>{policy.error.message}</span>
            : 'Действует на основной VPN-маршрут и на карточки с режимом «Как в настройках».'}>
            <Row label='Kill switch' hint={policy.data?.enabled === false
                ? 'При отказе VPN разрешён запасной прямой выход.'
                : 'Блокировать прямой выход, если выбранный VPN недоступен.'}
                trailing={policy.data
                    ? <Switch label='Общий kill switch' checked={policy.data.enabled} disabled={policy.busy}
                        onChange={enabled => { policy.reset(); if (enabled) policy.save({ enabled }); else setConfirming(true) }} />
                    : <span role='status' className='text-sm text-muted-foreground'>{policy.error ? 'Нет данных' : 'Загружаем…'}</span>} />
            {confirming && <ProtectionWarning title='Выключить общий kill switch?' confirmLabel='Выключить kill switch'
                busy={policy.busy} error={policy.error?.message}
                onCancel={() => { setConfirming(false); policy.reset() }}
                onConfirm={() => { policy.saveAsync({ enabled: false }).then(() => setConfirming(false), () => {}) }}>
                <p>Если выбранный VPN-сервер перестанет отвечать, основной маршрут и карточки с режимом «Как в настройках» смогут выйти в интернет <strong className='text-foreground'>напрямую</strong>, с домашнего адреса.</p>
                <p className='text-muted-foreground'>Карточки с режимом «Всегда включён» останутся защищены.</p>
            </ProtectionWarning>}
        </Group>
    )
}

export function ServiceKillSwitch({ policy, id, name, direct = false }: {
    policy: ReturnType<typeof useKillSwitch>; id: string; name: string; direct?: boolean
}) {
    const [pending, setPending] = useState<ServiceMode | null>(null)
    if (!policy.data) return null
    // With the route "direct" there is no VPN to fall back from.
    if (direct) return null
    const current = serviceKillSwitch(policy.data, id)
    const choose = (mode: ServiceMode) => {
        policy.reset()
        const lowers = current.enabled && (mode === 'off' || mode === 'inherit' && !policy.data!.enabled)
        if (lowers) setPending(mode)
        else policy.save({ service_id: id, mode })
    }
    return (
        <label className='mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-separator pt-2 text-sm'>
            <span className='font-medium'>Kill switch</span>
            <select aria-label={'Kill switch · ' + name} value={current.mode} disabled={policy.busy}
                className='min-h-10 max-w-full cursor-pointer rounded-lg bg-fill px-2 text-sm text-foreground disabled:opacity-60'
                onChange={event => {
                    const mode = event.target.value
                    if (mode === 'inherit' || mode === 'on' || mode === 'off') choose(mode)
                }}>
                <option value='inherit'>Как в настройках · {policy.data.enabled ? 'вкл.' : 'выкл.'}</option>
                <option value='on'>Всегда включён</option>
                <option value='off'>Всегда выключен</option>
            </select>
            {pending && <ProtectionWarning title={`Выключить kill switch · ${name}?`} confirmLabel='Выключить kill switch'
                busy={policy.busy} error={policy.error?.message}
                onCancel={() => { setPending(null); policy.reset() }}
                onConfirm={() => { policy.saveAsync({ service_id: id, mode: pending }).then(() => setPending(null), () => {}) }}>
                <p>Если VPN-сервер этой карточки перестанет отвечать, {name} сможет выйти в интернет <strong className='text-foreground'>напрямую</strong>, с домашнего адреса.</p>
                {id === 'claude' && <p className='rounded-xl bg-warning/10 p-3 text-warning'>Вместе с этим снимается фильтр API на роутере, который не выпускает запросы Claude напрямую даже при остановленном VPN.</p>}
                {isAiService(id) && id !== 'claude' && <p className='text-muted-foreground'>AI-сервисы могут ограничить аккаунт, если увидят вход с другого адреса.</p>}
            </ProtectionWarning>}
        </label>
    )
}
