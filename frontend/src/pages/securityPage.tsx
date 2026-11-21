import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconDeviceMobileMessage, IconFingerprint, IconKey, IconLifebuoy, IconLogout } from '@tabler/icons-react'
import { Group, IconTile, PageTitle, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { Sheet } from '@/components/sheet'
import { useAuth } from '@/hooks/useAuth'
import { api, setToken } from '@/lib/api'
import { plural } from '@/lib/format'
import { saveTextFile } from '@/lib/journal'
import { isIOSDevice, passkeySupported, registerPasskey } from '@/lib/webauthn'

type Account = { username: string; recovery_codes_left: number; passkeys: number; remember: boolean }
type Confirmation = { current_password: string; code: string }
type Task = 'password' | 'authenticator' | 'spare' | null

const field = 'mt-1.5 min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none focus:border-tint disabled:opacity-50'
const primary = 'min-h-12 w-full cursor-pointer rounded-xl bg-primary px-4 font-semibold text-primary-foreground disabled:cursor-default disabled:opacity-50'
const icon = (color: string, Glyph: typeof IconKey) => <IconTile color={color}><Glyph className='size-[17px]' stroke={2.2} /></IconTile>

// The current password and a code: asked before every change of a secret.
function ConfirmFields({ value, onChange, disabled }: { value: Confirmation; onChange: (next: Confirmation) => void; disabled?: boolean }) {
    return <>
        <label className='block py-3 text-[15px] font-medium'>Текущий пароль
            <input type='password' autoComplete='current-password' value={value.current_password} disabled={disabled}
                onChange={event => onChange({ ...value, current_password: event.target.value })} className={field} />
        </label>
        <label className='block py-3 text-[15px] font-medium'>Код из приложения-аутентификатора
            <input type='text' inputMode='text' autoComplete='one-time-code' value={value.code} disabled={disabled} maxLength={24}
                onChange={event => onChange({ ...value, code: event.target.value.trim() })} placeholder='000000' className={field} />
            <span className='mt-1 block text-[13px] font-normal text-muted-foreground'>Подойдёт и запасной код.</span>
        </label>
    </>
}

function Problem({ children }: { children: ReactNode }) {
    return children ? <p role='alert' className='px-4 text-sm text-destructive'>{children}</p> : null
}

export function SecurityPage() {
    const qc = useQueryClient()
    const { logout } = useAuth()
    const [task, setTask] = useState<Task>(null)
    const [confirm, setConfirm] = useState<Confirmation>({ current_password: '', code: '' })
    const [fresh, setFresh] = useState({ password: '', repeat: '' })
    const [binding, setBinding] = useState<{ totp_secret: string; totp_qr: string } | null>(null)
    const [bindCode, setBindCode] = useState('')
    const [codes, setCodes] = useState<string[] | null>(null)
    const [notice, setNotice] = useState('')
    const [ending, setEnding] = useState(false)
    const [removing, setRemoving] = useState(false)

    const account = useQuery({ queryKey: ['account'], queryFn: () => api.get<Account>('/api/account') })
    const passkeys = useQuery({ queryKey: ['passkeys'], queryFn: () => api.get<{ passkeys: string[] }>('/api/account/passkey') })
    const refresh = () => { void qc.invalidateQueries({ queryKey: ['account'] }) }
    const open = (next: Task) => {
        setTask(next); setConfirm({ current_password: '', code: '' }); setFresh({ password: '', repeat: '' })
        setBinding(null); setBindCode(''); setCodes(null); setNotice('')
        password.reset(); begin.reset(); bind.reset(); spare.reset()
    }
    const close = () => setTask(null)

    const password = useMutation({
        mutationFn: () => api.post<{ token: string }>('/api/account/password', { ...confirm, new_password: fresh.password }),
        onSuccess: data => { setToken(data.token); close(); setNotice('Пароль изменён. На остальных устройствах вход завершён.'); refresh() },
    })
    const begin = useMutation({
        mutationFn: () => api.post<{ totp_secret: string; totp_qr: string }>('/api/account/totp/begin', confirm),
        onSuccess: data => setBinding(data),
    })
    const bind = useMutation({
        mutationFn: () => api.post('/api/account/totp/confirm', { code: bindCode }),
        onSuccess: () => { close(); setNotice('Приложение привязано заново. Прежние запасные коды больше не действуют — создайте новые.'); refresh() },
    })
    const spare = useMutation({
        mutationFn: () => api.post<{ codes: string[] }>('/api/account/recovery-codes', confirm),
        onSuccess: data => { setCodes(data.codes); refresh() },
    })
    const endSessions = useMutation({
        mutationFn: () => api.post<{ token: string }>('/api/account/sessions/end', {}),
        onSuccess: data => { setToken(data.token); setEnding(false); setNotice('Вход на остальных устройствах завершён.') },
    })
    const addPasskey = useMutation({
        mutationFn: () => registerPasskey(),
        onSettled: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    })
    const removePasskey = useMutation({
        mutationFn: (id: string) => api.del('/api/account/passkey', { id }),
        onSuccess: () => setRemoving(false),
        onSettled: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    })

    const passkey = passkeys.data?.passkeys?.[0]
    const keyName = isIOSDevice() ? 'Face ID' : 'Ключ доступа'
    const left = account.data?.recovery_codes_left ?? 0
    const confirmReady = confirm.current_password.length > 0 && confirm.code.length >= 6
    const passwordReady = confirmReady && fresh.password.length >= 8 && fresh.password === fresh.repeat
    const submit = (run: () => void) => (event: FormEvent) => { event.preventDefault(); run() }

    return <>
        <PageTitle title='Вход и безопасность' subtitle={account.data ? 'Учётная запись · ' + account.data.username : undefined} back={{ to: '/settings', label: 'Настройки' }} />
        {notice && <p role='status' className='px-4 text-[15px] text-tint'>{notice}</p>}
        <Problem>{account.error?.message}</Problem>

        <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
            <Group title='Пароль и код'>
                <Row icon={icon('#0a84ff', IconKey)} label='Сменить пароль' hint='На остальных устройствах вход завершится.' tone='tint' onClick={() => open('password')} />
                <Row icon={icon('#5856d6', IconDeviceMobileMessage)} label='Привязать приложение заново' hint='Новый телефон или новое приложение-аутентификатор.' tone='tint' onClick={() => open('authenticator')} />
                <Row icon={icon('#ff9f0a', IconLifebuoy)} label='Запасные коды' tone='tint' onClick={() => open('spare')}
                    hint={left > 0 ? `Осталось ${left} ${plural(left, 'код', 'кода', 'кодов')}. Каждый заменяет код из приложения один раз.` : 'Не созданы. Пригодятся, если телефон с приложением потерян.'} />
            </Group>

            <Group title={keyName} footer={<Problem>{(addPasskey.error ?? passkeys.error)?.message}</Problem>}>
                {passkey ? <Row icon={icon('#30d158', IconFingerprint)} label={isIOSDevice() ? 'Вход по Face ID включён' : 'Ключ доступа сохранён'} hint='Вход без пароля и кода.'
                    trailing={<button type='button' onClick={() => { removePasskey.reset(); setRemoving(true) }} className='min-h-9 cursor-pointer px-1 text-[15px] text-destructive'>Удалить</button>} />
                    : passkeySupported() ? <Row icon={icon('#30d158', IconFingerprint)} tone='tint' disabled={addPasskey.isPending || !passkeys.isSuccess}
                        label={addPasskey.isPending ? 'Создаю ключ…' : isIOSDevice() ? 'Включить вход по Face ID' : 'Создать ключ доступа'}
                        hint='Вход по отпечатку, лицу или PIN-коду устройства.' onClick={() => addPasskey.mutate()} />
                        : <Row icon={icon('#30d158', IconFingerprint)} label='Нужен защищённый адрес' hint='Ключ доступа создаётся только на HTTPS-адресе панели.' to='/settings/access' />}
                <Row label='Адрес панели и QR-код' to='/settings/access' />
            </Group>

            <Group title='Устройства' footer={account.data?.remember ? 'Это устройство запомнено: вход сохраняется, пока вы пользуетесь панелью.' : 'Вход на этом устройстве закончится через сутки. Отметка «Запомнить это устройство» при входе продлевает его.'}>
                <Row icon={icon('#ff453a', IconLogout)} label='Выйти на всех остальных устройствах' tone='tint' onClick={() => { endSessions.reset(); setEnding(true) }} />
                <Row label='Выйти на этом устройстве' tone='destructive' onClick={logout} />
            </Group>
        </div>

        <Sheet open={task === 'password'} onClose={close} title='Смена пароля'>
            <form onSubmit={submit(() => password.mutate())} className='flex flex-col gap-5'>
                <Group>
                    <ConfirmFields value={confirm} onChange={setConfirm} disabled={password.isPending} />
                </Group>
                <Group footer='От 8 символов. После смены вход на остальных устройствах завершится.'>
                    <label className='block py-3 text-[15px] font-medium'>Новый пароль
                        <input type='password' autoComplete='new-password' value={fresh.password} disabled={password.isPending}
                            onChange={event => setFresh({ ...fresh, password: event.target.value })} className={field} />
                    </label>
                    <label className='block py-3 text-[15px] font-medium'>Новый пароль ещё раз
                        <input type='password' autoComplete='new-password' value={fresh.repeat} disabled={password.isPending}
                            onChange={event => setFresh({ ...fresh, repeat: event.target.value })} className={field} />
                    </label>
                </Group>
                <Problem>{password.error?.message ?? (fresh.repeat && fresh.password !== fresh.repeat ? 'Пароли не совпадают.' : '')}</Problem>
                <button type='submit' disabled={!passwordReady || password.isPending} className={primary}>{password.isPending ? 'Сохраняем…' : 'Сменить пароль'}</button>
            </form>
        </Sheet>

        <Sheet open={task === 'authenticator'} onClose={close} title='Новая привязка приложения'>
            {!binding ? <form onSubmit={submit(() => begin.mutate())} className='flex flex-col gap-5'>
                <Group footer='Прежнее приложение работает, пока новое не покажет верный код.'>
                    <ConfirmFields value={confirm} onChange={setConfirm} disabled={begin.isPending} />
                </Group>
                <Problem>{begin.error?.message}</Problem>
                <button type='submit' disabled={!confirmReady || begin.isPending} className={primary}>{begin.isPending ? 'Проверяем…' : 'Продолжить'}</button>
            </form> : <form onSubmit={submit(() => bind.mutate())} className='flex flex-col gap-5'>
                <Group footer='Отсканируйте QR-код в новом приложении или введите секрет вручную.'>
                    <div className='flex justify-center py-4'><img src={binding.totp_qr} alt='QR-код для приложения-аутентификатора' className='size-56 rounded-xl bg-white p-2' /></div>
                    <p className='select-all break-all py-3 font-mono text-sm'>{binding.totp_secret}</p>
                </Group>
                <Group>
                    <label className='block py-3 text-[15px] font-medium'>Код из нового приложения
                        <input type='text' inputMode='numeric' autoComplete='one-time-code' maxLength={6} value={bindCode} disabled={bind.isPending} autoFocus
                            onChange={event => setBindCode(event.target.value.replace(/\D/g, ''))} placeholder='000000' className={field + ' text-center text-xl tracking-[0.3em]'} />
                    </label>
                </Group>
                <Problem>{bind.error?.message}</Problem>
                <button type='submit' disabled={bindCode.length !== 6 || bind.isPending} className={primary}>{bind.isPending ? 'Проверяем…' : 'Привязать'}</button>
            </form>}
        </Sheet>

        <Sheet open={task === 'spare'} onClose={close} title='Запасные коды' closeLabel={codes ? 'Готово' : 'Отмена'}>
            {!codes ? <form onSubmit={submit(() => spare.mutate())} className='flex flex-col gap-5'>
                <Group footer={left > 0 ? 'Новые коды заменят прежние: старые перестанут действовать.' : 'Десять кодов. Каждый один раз заменяет код из приложения при входе.'}>
                    <ConfirmFields value={confirm} onChange={setConfirm} disabled={spare.isPending} />
                </Group>
                <Problem>{spare.error?.message}</Problem>
                <button type='submit' disabled={!confirmReady || spare.isPending} className={primary}>{spare.isPending ? 'Создаём…' : 'Создать коды'}</button>
            </form> : <div className='flex flex-col gap-5'>
                <Group footer='Сохраните их сейчас: панель хранит только отпечатки и показать коды ещё раз не сможет.'>
                    <ul className='grid grid-cols-1 gap-x-6 gap-y-2 py-4 font-mono text-[15px] sm:grid-cols-2'>
                        {codes.map(code => <li key={code} className='select-all'>{code}</li>)}
                    </ul>
                </Group>
                <button type='button' className={primary} onClick={() => saveTextFile('xkeen-panel-codes.txt', 'Запасные коды входа в панель XKeen\n\n' + codes.join('\n') + '\n')}>Скачать файлом</button>
                <button type='button' className='min-h-11 cursor-pointer text-tint' onClick={() => void navigator.clipboard?.writeText(codes.join('\n'))}>Скопировать</button>
            </div>}
        </Sheet>

        {ending && <ProtectionWarning title='Выйти на остальных устройствах?' confirmLabel='Завершить входы' delay={0}
            busy={endSessions.isPending} error={endSessions.error?.message}
            onCancel={() => setEnding(false)} onConfirm={() => endSessions.mutate()}>
            <p>На всех телефонах и компьютерах, кроме этого, панель попросит войти заново.</p>
        </ProtectionWarning>}
        {removing && passkey && <ProtectionWarning title='Удалить ключ доступа?' confirmLabel='Удалить ключ' delay={0}
            busy={removePasskey.isPending} error={removePasskey.error?.message}
            onCancel={() => { setRemoving(false); removePasskey.reset() }} onConfirm={() => removePasskey.mutate(passkey)}>
            <p>Вход по Face ID или ключу доступа перестанет работать на всех устройствах. Войти можно будет с паролем и кодом из приложения.</p>
        </ProtectionWarning>}
    </>
}
