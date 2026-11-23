import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { IconArrowsExchange, IconBan, IconChevronRight, IconRefresh } from '@tabler/icons-react'
import { Group, IconTile, Row, Switch } from '@/components/ios'
import { CountriesSheet, RefreshSheet, intervalLabel } from '@/components/settingsSheets'
import { usePanelSettings, useServers, useStatus } from '@/hooks/usePanelData'
import { countryName, serverCountry } from '@/lib/format'
import { api } from '@/lib/api'
import type { PanelSettings, Status } from '@/types'

const icon = (color: string, Glyph: typeof IconBan) => (
    <IconTile color={color}><Glyph className='size-[17px]' stroke={2.2} /></IconTile>
)
const chevron = <IconChevronRight className='size-4 shrink-0 text-label-tertiary' stroke={2.6} />

function useSaveSettings() {
    const qc = useQueryClient()
    return useMutation({
        mutationFn: (next: PanelSettings) =>
            api.put<PanelSettings>('/api/panel/settings', next),
        onSuccess: data => {
            qc.setQueryData(['panel-settings'], data)
            for (const key of ['pool', 'multipools', 'servers', 'service-routes', 'status']) {
                void qc.invalidateQueries({ queryKey: [key] })
            }
        },
    })
}

const avoidedOf = (settings?: PanelSettings) =>
    [...new Set((settings?.avoid_countries ?? []).map(code => code.trim().toUpperCase()))]

// The locations automatic choice and replacement skip. Shown both in the
// automation settings and on the servers screen; a location is the country
// label a subscription gives its server.
export function ExcludedLocations() {
    const servers = useServers()
    const countries = useMemo(() => {
        const codes = new Set<string>()
        for (const server of servers.data ?? []) {
            const code = serverCountry(server).trim()
            if (server.protocol !== 'xray-profile' && /^[A-Z]{2}$/.test(code)) codes.add(code)
        }
        return [...codes].sort((a, b) => countryName(a).localeCompare(countryName(b), 'ru'))
    }, [servers.data])
    const [open, setOpen] = useState(false)
    const settings = usePanelSettings()
    const saveSettings = useSaveSettings()
    const avoid = avoidedOf(settings.data)
    const visibleAvoid = countries.filter(code => avoid.includes(code))
    const countryStatus = !servers.data && (servers.isError ? 'Каталог недоступен' : 'Загрузка…')

    return (
        <>
            <Row
                icon={icon('#ff453a', IconBan)}
                label='Исключенные локации'
                hint={countryStatus || (settings.data
                    ? visibleAvoid.map(code => countryName(code)).join(', ') || 'Нет: автовыбор берёт все локации'
                    : '—')}
                onClick={() => setOpen(true)}
                disabled={!settings.data}
                trailing={chevron}
            />
            <CountriesSheet
                open={open}
                onClose={() => setOpen(false)}
                value={avoid}
                candidates={countries}
                catalogStatus={countryStatus || undefined}
                onRetry={servers.isError ? () => { void servers.refetch() } : undefined}
                onSave={avoid_countries =>
                    saveSettings.mutateAsync({
                        avoid_countries,
                        subscription_refresh_minutes: settings.data?.subscription_refresh_minutes ?? 0,
                    })
                }
            />
        </>
    )
}

export function ServerAutomation() {
    const qc = useQueryClient()
    const status = useStatus().data
    const watchdog = useMutation({
        mutationFn: (active: boolean) =>
            api.post('/api/watchdog/toggle', { active }),
        onMutate: active =>
            qc.setQueryData<Status>(['status'], old =>
                old ? { ...old, watchdog_active: active } : old,
            ),
        onSettled: () => qc.invalidateQueries({ queryKey: ['status'] }),
    })

    const [sheet, setSheet] = useState<'refresh' | null>(null)
    const settings = usePanelSettings()
    const saveSettings = useSaveSettings()
    const refresh = settings.data?.subscription_refresh_minutes ?? 0

    return (
        <>
            <Group
                title='Автоматика'
                footer={status?.core === 'mihomo'
                    ? 'Автовыбором управляет Mihomo. Если включить замену, панель сможет заменить недоступный общий сервер проверенным сервером той же страны. Карточки сервисов и сборные профили сохраняют выбранный маршрут.'
                    : 'Панель проверяет связь через VPN каждые 2 минуты. Если сервер перестал работать, она переключится на другой — при ручном выборе на сервер той же страны.'}
            >
                <Row
                    icon={icon('#30d158', IconArrowsExchange)}
                    label='Менять упавший сервер'
                    trailing={
                        <Switch
                            checked={status?.watchdog_active ?? false}
                            onChange={active => watchdog.mutate(active)}
                            label='Менять упавший сервер'
                            disabled={!status || watchdog.isPending}
                        />
                    }
                />
                <ExcludedLocations />
                <Row
                    icon={icon('#ff9f0a', IconRefresh)}
                    label='Обновлять подписки'
                    detail={intervalLabel(refresh)}
                    onClick={() => setSheet('refresh')}
                    disabled={!settings.data}
                    trailing={chevron}
                />
            </Group>

            <RefreshSheet
                open={sheet === 'refresh'}
                onClose={() => setSheet(null)}
                value={refresh}
                onSave={subscription_refresh_minutes =>
                    saveSettings.mutateAsync({
                        avoid_countries: avoidedOf(settings.data),
                        subscription_refresh_minutes,
                    })
                }
            />
            {watchdog.error && <p role='alert' className='px-4 text-sm text-destructive'>{watchdog.error.message}</p>}
        </>
    )
}
