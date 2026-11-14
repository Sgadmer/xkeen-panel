import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
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
        mutationFn: () => api.post<ProbeJob>(path),
        onSuccess: job => qc.setQueryData(key, job),
        onSettled: () => qc.invalidateQueries({ queryKey: key }),
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
    const measured = new Map(job?.results.map(m => [m.id, m.latency_ms]))
    const pending = new Set(
        job?.running ? job.ids.filter(id => !measured.has(id)) : [],
    )
    return {
        check: () => {
            if (!start.isPending && !running) start.mutate()
        },
        checking: start.isPending || !!running || status.isLoading,
        error:
            start.error?.message || status.error?.message || job?.error || '',
        progress: { completed: measured.size, total: job?.ids.length ?? 0 },
        isPendingServer: (id: number) => pending.has(id),
        latencyFor: (id: number) => (running ? measured.get(id) : undefined),
    }
}
