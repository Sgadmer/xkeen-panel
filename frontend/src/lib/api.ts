const TOKEN_KEY = 'xkeen_token'

export const getToken = () => localStorage.getItem(TOKEN_KEY)
export const setToken = (token: string) =>
    localStorage.setItem(TOKEN_KEY, token)
export const clearToken = () => localStorage.removeItem(TOKEN_KEY)

export class ApiError extends Error {
    status: number
    // What the panel sent along with the error, when it sent anything.
    body?: unknown
    constructor(message: string, status: number, body?: unknown) {
        super(message)
        this.status = status
        this.body = body
    }
}

// Shown when the answer is not the panel's own: the request failed on the way,
// or the router's proxy answered with its error page while the panel restarts.
const UNAVAILABLE = 'Панель сейчас не отвечает. Возможно, она перезапускается — повторите через несколько секунд.'

function waitHint(resp: Response) {
    const seconds = Number(resp.headers.get('Retry-After'))
    if (!Number.isFinite(seconds) || seconds <= 0) return ''
    return seconds < 90 ? ` Повторите через ${Math.ceil(seconds)} с.` : ` Повторите через ${Math.ceil(seconds / 60)} мин.`
}

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
    const token = getToken()
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(options.headers as Record<string, string>),
    }

    if (token) {
        headers['Authorization'] = `Bearer ${token}`
    }

    let resp: Response
    try {
        resp = await fetch(url, { ...options, headers })
    } catch {
        throw new ApiError(UNAVAILABLE, 0)
    }

    // A 401 means an expired session only for authenticated requests. Login
    // endpoints are excluded — there may be no token yet, or a stale one on
    // /login — and their 401 is bad credentials, which the form must show.
    const isLogin = url.startsWith('/api/auth/login')
    if (resp.status === 401 && token && !isLogin) {
        clearToken()
        window.location.href = '/login'
        throw new ApiError('Сессия истекла', 401)
    }

    let data: { error?: string } | null = null
    try {
        data = await resp.json()
    } catch {
        // Not JSON: handled below as an answer that did not come from the panel.
    }

    if (!resp.ok) {
        const message = data?.error
            ? data.error.charAt(0).toUpperCase() + data.error.slice(1) + (resp.status === 429 || resp.status === 503 ? '.' + waitHint(resp) : '')
            : UNAVAILABLE
        throw new ApiError(message, resp.status, data ?? undefined)
    }
    if (data === null) throw new ApiError(UNAVAILABLE, resp.status)

    return data as T
}

export const api = {
    get: <T>(url: string) => request<T>(url),
    post: <T>(url: string, body?: unknown) =>
        request<T>(url, {
            method: 'POST',
            body: body ? JSON.stringify(body) : undefined,
        }),
    put: <T>(url: string, body?: unknown) =>
        request<T>(url, {
            method: 'PUT',
            body: body ? JSON.stringify(body) : undefined,
        }),
    del: <T>(url: string, body?: unknown) =>
        request<T>(url, {
            method: 'DELETE',
            body: body ? JSON.stringify(body) : undefined,
        }),
}

// A remembered device keeps its session while the panel is in use: the server
// hands out a fresh token once the current one is half a day old.
export async function refreshSession() {
    if (!getToken()) return
    try {
        const answer = await request<{ token?: string }>('/api/session/refresh', { method: 'POST' })
        if (answer.token) setToken(answer.token)
    } catch {
        // The next visit tries again; an expired session is handled by request().
    }
}
