import { useEffect } from 'react'
import { useMutation, useMutationState, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'

type ProbeJob = {
    run: number
    running: boolean
    ids: number[]
    results: { id: number; latency_ms: number }[]
    error?: string
}

const path = '/api/servers/check/job'
const key = ['server-check-job']
const startKey = ['server-check-start']

export function useStreamLatency() {
    const qc = useQueryClient()
    const status = useQuery({
        queryKey: key,
        queryFn: () => api.get<ProbeJob>(path),
        staleTime: 0,
        refetchOnMount: 'always',
        refetchInterval: query => (query.state.data?.running ? 1000 : 8000),
        refetchIntervalInBackground: false,
    })
    const start = useMutation({
        mutationKey: startKey,
        mutationFn: (ids?: number[]) =>
            api.post<ProbeJob>(path, ids === undefined ? undefined : { server_ids: ids }),
        onMutate: () => qc.cancelQueries({ queryKey: key }),
        onSuccess: job => qc.setQueryData(key, job),
        onSettled: () => { void qc.invalidateQueries({ queryKey: key }) },
    })
    const starts = useMutationState({
        filters: { mutationKey: startKey, status: 'pending' },
        select: mutation => mutation.state.variables as number[] | undefined,
    })
    const job = status.data
    const run = job?.run
    const running = job?.running
    useEffect(() => {
        if (!run || running) return
        for (const name of ['servers', 'pool', 'multipools', 'status']) {
            void qc.invalidateQueries({ queryKey: [name] })
        }
    }, [qc, run, running])
    const starting = starts.length > 0 && !running
    const startingIds = starting
        ? starts[0] ?? qc.getQueryData<{ id: number }[]>(['servers'])?.map(s => s.id) ?? []
        : []
    const measured = new Map(starting ? [] : job?.results.map(m => [m.id, m.latency_ms]))
    const pending = new Set(
        job?.running ? job.ids.filter(id => !measured.has(id)) : startingIds,
    )
    return {
        check: (ids?: number[]) => {
            if (!running && !qc.isMutating({ mutationKey: startKey })) start.mutate(ids)
        },
        checking: starting || !!running || status.isLoading,
        error:
            start.error?.message || status.error?.message || job?.error || '',
        progress: { completed: measured.size, total: starting ? pending.size : job?.ids.length ?? 0 },
        isPendingServer: (id: number) => (starting && starts[0] === undefined) || pending.has(id),
        latencyFor: (id: number) => (running ? measured.get(id) : undefined),
    }
}
