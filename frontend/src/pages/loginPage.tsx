import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
    Card,
    CardContent,
    CardHeader,
    CardTitle,
    CardDescription,
} from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Logo } from '@/components/logo'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { IconFingerprint } from '@tabler/icons-react'
import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { isIOSDevice, passkeySupported } from '@/lib/webauthn'
import type { AuthStatus } from '@/types'

const REMEMBER_KEY = 'xkeen_remember_device'

function rememberedChoice() {
    try {
        return localStorage.getItem(REMEMBER_KEY) === '1'
    } catch {
        return false
    }
}

export function LoginPage() {
    const { login, loginWithPasskey } = useAuth()
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [code, setCode] = useState('')
    const [spare, setSpare] = useState(false)
    const [remember, setRemember] = useState(rememberedChoice)
    const [error, setError] = useState('')

    const keepChoice = (value: boolean) => {
        setRemember(value)
        try {
            localStorage.setItem(REMEMBER_KEY, value ? '1' : '0')
        } catch {
            // The choice still applies to this sign-in.
        }
    }

    const loginMutation = useMutation({
        mutationFn: () => login(username, password, code, remember),
        onError: (err: Error) => setError(err.message),
    })

    const authStatus = useQuery({
        queryKey: ['authStatus'],
        queryFn: () => api.get<AuthStatus>('/api/auth/status'),
    })

    const passkeyMutation = useMutation({
        mutationFn: () => loginWithPasskey(remember),
        onError: (err: Error) => setError(err.message),
    })

    const showPasskey = passkeySupported() && authStatus.data?.passkey_enabled
    const codeReady = spare ? code.replace(/[\s-]/g, '').length === 16 : code.length === 6

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        loginMutation.mutate()
    }

    return (
        <div className='min-h-screen flex items-center justify-center p-4'>
            <div aria-hidden className='bg-page fixed inset-0 -z-10' />
            <div className='w-full max-w-md'>
                <div className='mb-5 flex justify-center'>
                    <Logo size={56} />
                </div>
                <Card>
                    <CardHeader className='text-center'>
                        <CardTitle className='text-2xl'>XKeen</CardTitle>
                        <CardDescription>
                            Вход в панель управления
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {showPasskey && (
                            <>
                                <Button
                                    type='button'
                                    className='w-full'
                                    onClick={() => {
                                        setError('')
                                        passkeyMutation.mutate()
                                    }}
                                    disabled={passkeyMutation.isPending}
                                >
                                    <IconFingerprint className='size-4' />
                                    {passkeyMutation.isPending
                                        ? 'Проверка...'
                                        : isIOSDevice() ? 'Войти по Face ID' : 'Войти с ключом доступа'}
                                </Button>
                                <div className='my-4 flex items-center gap-3 text-xs text-muted-foreground'>
                                    <span className='h-px flex-1 bg-border' />
                                    или
                                    <span className='h-px flex-1 bg-border' />
                                </div>
                            </>
                        )}

                        {error && (
                            <div role='alert' className='mb-4 p-3 bg-destructive/10 border border-destructive/30 rounded-lg text-sm text-destructive'>
                                {error}
                            </div>
                        )}

                        <form
                            onSubmit={handleSubmit}
                            className='space-y-4'
                            autoComplete='on'
                        >
                            <div className='space-y-2'>
                                <Label htmlFor='login-username'>Логин</Label>
                                <Input
                                    id='login-username'
                                    name='username'
                                    autoComplete='username'
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>
                            <div className='space-y-2'>
                                <Label htmlFor='login-password'>Пароль</Label>
                                <Input
                                    id='login-password'
                                    name='password'
                                    type='password'
                                    autoComplete='current-password'
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    required
                                />
                            </div>
                            <div className='space-y-2'>
                                <Label htmlFor='login-totp'>{spare ? 'Запасной код' : 'Код из приложения-аутентификатора'}</Label>
                                {spare ? (
                                    <Input
                                        id='login-totp'
                                        name='spare-code'
                                        type='text'
                                        autoComplete='off'
                                        autoCapitalize='characters'
                                        spellCheck={false}
                                        maxLength={24}
                                        value={code}
                                        onChange={e => setCode(e.target.value.toUpperCase())}
                                        placeholder='XXXX-XXXX-XXXX-XXXX'
                                        required
                                        className='text-center text-lg tracking-[0.12em]'
                                    />
                                ) : (
                                    <Input
                                        id='login-totp'
                                        name='totp'
                                        type='text'
                                        inputMode='numeric'
                                        autoComplete='one-time-code'
                                        pattern='[0-9]*'
                                        maxLength={6}
                                        value={code}
                                        onChange={e =>
                                            setCode(
                                                e.target.value.replace(/\D/g, ''),
                                            )
                                        }
                                        placeholder='000000'
                                        required
                                        className='text-center text-xl tracking-[0.3em] placeholder:tracking-[0.3em]'
                                    />
                                )}
                                <button
                                    type='button'
                                    className='min-h-9 cursor-pointer text-sm text-tint'
                                    onClick={() => { setSpare(value => !value); setCode(''); setError('') }}
                                >
                                    {spare ? 'Ввести код из приложения' : 'Нет доступа к приложению? Ввести запасной код'}
                                </button>
                            </div>
                            <label className='flex min-h-11 cursor-pointer items-start gap-3 text-sm'>
                                <input
                                    type='checkbox'
                                    checked={remember}
                                    onChange={e => keepChoice(e.target.checked)}
                                    className='mt-0.5 size-5 shrink-0 accent-[var(--primary)]'
                                />
                                <span>
                                    Запомнить это устройство
                                    <span className='block text-xs text-muted-foreground'>
                                        Вход сохранится, пока вы пользуетесь панелью, и закончится через 30 дней без посещений. Без отметки — через сутки.
                                    </span>
                                </span>
                            </label>
                            <Button
                                type='submit'
                                disabled={
                                    loginMutation.isPending ||
                                    !codeReady
                                }
                                className='w-full'
                            >
                                {loginMutation.isPending ? 'Вход...' : 'Войти'}
                            </Button>
                        </form>
                    </CardContent>
                </Card>
            </div>
        </div>
    )
}
