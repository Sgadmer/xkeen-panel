import { useSyncExternalStore } from 'react'

// Whether the panel's event stream is connected. The router serves a limited
// number of streams; a tab left without one falls back to asking periodically.
let connected = false
const listeners = new Set<() => void>()

export function setLiveUpdates(value: boolean) {
    if (connected === value) return
    connected = value
    listeners.forEach(listener => listener())
}

export function useLiveUpdates() {
    return useSyncExternalStore(
        listener => {
            listeners.add(listener)
            return () => listeners.delete(listener)
        },
        () => connected,
    )
}
