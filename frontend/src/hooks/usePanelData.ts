import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useLiveUpdates } from '@/lib/liveUpdates'
import type {
    AutoScope,
    DevicesResponse,
    MultiPool,
    PanelSettings,
    PoolStatus,
    Server,
    ServerSource,
    SitesResponse,
    Status,
    SubscriptionInfo,
    UpdateState,
} from '@/types'

export function useStatus() {
    // The event stream normally pushes the status. Without it, ask now and then.
    const live = useLiveUpdates()
    return useQuery({
        queryKey: ['status'],
        queryFn: () => api.get<Status>('/api/status'),
        refetchInterval: live ? false : 10000,
    })
}

export function useServers() {
    return useQuery({
        queryKey: ['servers'],
        queryFn: () =>
            api
                .get<{ servers: Server[] }>('/api/servers')
                .then(d => d.servers ?? []),
    })
}

export function usePool() {
    return useQuery({
        queryKey: ['pool'],
        queryFn: () => api.get<PoolStatus>('/api/pool'),
    })
}

export function usePanelSettings() {
    return useQuery({
        queryKey: ['panel-settings'],
        queryFn: () => api.get<PanelSettings>('/api/panel/settings'),
    })
}

export function useSites() {
    return useQuery({
        queryKey: ['sites'],
        queryFn: () => api.get<SitesResponse>('/api/sites'),
    })
}

export function useSubscription() {
    return useQuery({
        queryKey: ['subscription'],
        queryFn: () => api.get<SubscriptionInfo>('/api/subscription'),
    })
}

export function useServerSources() {
    return useQuery({
        queryKey: ['sources'],
        queryFn: () => api.get<{ sources: ServerSource[] }>('/api/sources').then(data => data.sources ?? []),
    })
}

export function useMultiPools(enabled = true) {
    return useQuery({
        queryKey: ['multipools'],
        enabled,
        queryFn: () => api.get<{ pools: MultiPool[]; scopes: AutoScope[] }>('/api/multipools'),
    })
}

export function useLogs() {
    return useQuery({
        queryKey: ['logs'],
        queryFn: () =>
            api
                .get<{ lines: string[] }>('/api/logs?lines=200')
                .then(d => d.lines ?? []),
    })
}

export function useDevices() {
    return useQuery({
        queryKey: ['devices'],
        queryFn: () => api.get<DevicesResponse>('/api/devices'),
        refetchInterval: 60000,
    })
}

export function useUpdate() {
    return useQuery({
        queryKey: ['update'],
        queryFn: () => api.get<UpdateState>('/api/update'),
    })
}
