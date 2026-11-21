import type { AuthStatus } from '@/types'

const SKIP = 'xkeen.plain-address.until'

// Opened by its plain address while a working HTTPS address exists: move
// there, so the password and the session travel encrypted.
//
// The router has already checked that address. This browser checks it too —
// a device with its own DNS may not reach the home-only name — and stays where
// it is when the check fails, so the panel is never out of reach.
export async function moveToSecureAddress(status: AuthStatus): Promise<boolean> {
    if (window.location.protocol !== 'http:' || !status.https_url) return false
    let target: URL
    try {
        target = new URL(status.https_url)
    } catch {
        return false
    }
    if (target.protocol !== 'https:' || target.hostname === window.location.hostname) return false
    // ?plain=1 keeps this tab on the plain address, for troubleshooting.
    if (new URLSearchParams(window.location.search).get('plain') === '1') {
        try { sessionStorage.setItem(SKIP, String(Date.now() + 60 * 60 * 1000)) } catch { /* this tab only */ }
        return false
    }
    try {
        if (Number(sessionStorage.getItem(SKIP)) > Date.now()) return false
    } catch { /* no storage: check every time */ }
    try {
        await fetch(new URL('api/auth/status', target), { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(2500) })
    } catch {
        // Not reachable from this device right now. Do not ask again for a few minutes.
        try { sessionStorage.setItem(SKIP, String(Date.now() + 5 * 60 * 1000)) } catch { /* this tab only */ }
        return false
    }
    window.location.replace(new URL(window.location.pathname + window.location.search + window.location.hash, target).href)
    return true
}
