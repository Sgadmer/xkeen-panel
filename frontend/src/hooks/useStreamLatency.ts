import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { getToken, clearToken } from '@/lib/api'
import type { Server } from '@/types'

export function useStreamLatency() {
    const qc = useQueryClient()
    const [checking, setChecking] = useState(false)
    const [error, setError] = useState('')
    const [progress, setProgress] = useState({ completed: 0, total: 0 })
    const esRef = useRef<EventSource | null>(null)

    useEffect(
        () => () => {
            esRef.current?.close()
            esRef.current = null
        },
        [],
    )

    const check = useCallback(() => {
        if (esRef.current) return

        const token = getToken()
        if (!token) return

        setChecking(true)
        setError('')
        setProgress({ completed: 0, total: 0 })
        const es = new EventSource(
            `/api/servers/check?token=${encodeURIComponent(token)}`,
        )
        esRef.current = es

        const finish = () => {
            setChecking(false)
            es.close()
            esRef.current = null
        }

        es.addEventListener('progress', e => {
            try {
                const value = JSON.parse(e.data)
                if (
                    Number.isInteger(value.completed) &&
                    Number.isInteger(value.total)
                ) {
                    setProgress({
                        completed: value.completed,
                        total: value.total,
                    })
                }
            } catch {
                // A heartbeat or interrupted frame carries no measurement.
            }
        })

        es.addEventListener('latency', e => {
            let value: { id: number; latency_ms: number; last_checked?: string }
            try {
                value = JSON.parse(e.data)
            } catch {
                return
            }
            const { id, latency_ms, last_checked } = value
            if (!Number.isInteger(id) || !Number.isFinite(latency_ms)) return
            qc.setQueryData<Server[]>(['servers'], old =>
                old?.map(s =>
                    s.id === id
                        ? {
                              ...s,
                              latency_ms,
                              probe_kind: 'https',
                              last_checked,
                          }
                        : s,
                ),
            )
        })

        es.addEventListener('done', () => {
            finish()
            qc.invalidateQueries({ queryKey: ['servers'] })
            qc.invalidateQueries({ queryKey: ['pool'] })
        })

        es.addEventListener('failure', () => {
            setError('Не удалось выполнить HTTPS-проверку. Повторите попытку.')
            finish()
        })

        es.addEventListener('close', () => {
            finish()
        })

        es.onerror = () => {
            setError('Связь с HTTPS-проверкой прервалась. Повторите попытку.')
            finish()

            if (!getToken()) {
                clearToken()
                window.location.href = '/login'
            }
        }
    }, [qc])

    return { check, checking, error, progress }
}
