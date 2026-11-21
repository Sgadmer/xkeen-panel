import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RouterMetrics, type RouterSample } from '@/components/routerMetrics'
import { api } from '@/lib/api'

type Activity = { system: RouterSample; history?: RouterSample[] }

function useTabVisible() {
    const [visible, setVisible] = useState(() => document.visibilityState !== 'hidden')
    useEffect(() => {
        const update = () => setVisible(document.visibilityState !== 'hidden')
        document.addEventListener('visibilitychange', update)
        return () => document.removeEventListener('visibilitychange', update)
    }, [])
    return visible
}

// Processor, memory, temperature and traffic of the router. The router is not
// asked while the tab is in the background.
export function RouterActivity() {
    const visible = useTabVisible()
    const activity = useQuery({
        queryKey: ['router-load'],
        queryFn: () => api.get<Activity>('/api/diagnostics?connections=0'),
        refetchInterval: visible ? 5000 : false,
        retry: false,
        gcTime: 0,
    })
    return <RouterMetrics system={activity.data?.system} history={activity.data?.history} />
}
