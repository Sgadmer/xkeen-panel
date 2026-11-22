import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useStatus } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import type { Status } from '@/types'

// One XKeen restart button for every screen: the second tap within four
// seconds starts it, and the outcome stays on screen until the next attempt.
export function useXkeenRestart() {
    const qc = useQueryClient()
    const status = useStatus().data
    const [confirming, setConfirming] = useState(false)
    const timer = useRef<ReturnType<typeof setTimeout>>(undefined)
    useEffect(() => () => clearTimeout(timer.current), [])

    const restart = useMutation({
        mutationFn: () => api.post('/api/xkeen/restart'),
        onMutate: () => qc.setQueryData<Status>(['status'], old => old ? { ...old, restarting: true } : old),
        onSettled: () => {
            qc.invalidateQueries({ queryKey: ['status'] })
            qc.invalidateQueries({ queryKey: ['pool'] })
        },
    })

    const busy = restart.isPending || !!status?.restarting
    const click = () => {
        clearTimeout(timer.current)
        if (confirming) {
            setConfirming(false)
            restart.mutate()
            return
        }
        restart.reset()
        setConfirming(true)
        timer.current = setTimeout(() => setConfirming(false), 4000)
    }

    return {
        click,
        reset: restart.reset,
        busy,
        pending: restart.isPending,
        done: restart.isSuccess,
        label: busy ? 'Перезапускаем XKeen…' : confirming ? 'Нажмите ещё раз для перезапуска' : 'Перезапустить XKeen',
        // Shown where the button is: the result of the last attempt.
        result: restart.isPending ? null
            : restart.error ? <span role='alert' className='text-destructive'>Перезапуск не удался. {restart.error.message}</span>
            : restart.isSuccess ? <span role='status' className='text-success'>XKeen перезапущен.</span>
            : null,
    }
}

export type XkeenRestart = ReturnType<typeof useXkeenRestart>
