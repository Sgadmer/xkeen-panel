import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getToken, setToken, clearToken, api } from '@/lib/api'
import { getPasskeyToken } from '@/lib/webauthn'

export const useAuth = () => {
    const navigate = useNavigate()

    const login = useCallback(
        async (username: string, password: string, code: string, remember = false) => {
            const data = await api.post<{ token: string }>('/api/auth/login', {
                username,
                password,
                totp_code: code,
                remember,
            })
            setToken(data.token)
            navigate('/')
        },
        [navigate],
    )

    const loginWithPasskey = useCallback(async (remember = false) => {
        const token = await getPasskeyToken(remember)
        setToken(token)
        navigate('/')
    }, [navigate])

    const logout = useCallback(() => {
        clearToken()
        navigate('/login')
    }, [navigate])

    return {
        token: getToken(),
        isAuthenticated: !!getToken(),
        login,
        loginWithPasskey,
        logout,
    }
}
