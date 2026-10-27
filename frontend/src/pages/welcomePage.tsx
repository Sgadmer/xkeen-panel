import { useEffect, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
    IconCircleCheckFilled,
    IconCircleDashed,
    IconDeviceDesktop,
    IconLink,
    IconLoader2,
    IconPlayerPlay,
    IconTerminal2,
} from '@tabler/icons-react'
import { DeviceGroups, NewDevicesGroup } from '@/components/deviceList'
import { Group, Row } from '@/components/ios'
import { Logo } from '@/components/logo'
import { ServerSourceForm } from '@/components/serverSourceForm'
import { RoutingModeForm } from '@/pages/routingModePage'
import { useDevices, useStatus } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

export type SetupState = {
    xkeen_installed: boolean
    xkeen_version: string
    core: string
    core_running: boolean
    autostart: boolean
    subscription: boolean
    servers: number
    configured: boolean
    routing_mode_configured: boolean
    pool_nodes: number
    router_api: boolean
    policy_found: boolean
    devices_in_vpn: number
    new_devices_vpn: boolean
    watchdog: boolean
    complete: boolean
}

type StepId = 'xkeen' | 'subscription' | 'routing' | 'devices' | 'start'

const STEPS: StepId[] = ['subscription', 'routing', 'devices', 'start']

export const SETUP_LATER_KEY = 'xkeen_setup_later'

export function useSetupState() {
    return useQuery({
        queryKey: ['setup'],
        queryFn: () => api.get<SetupState>('/api/setup/state'),
    })
}

function firstStep(s: SetupState): StepId {
    if (!s.xkeen_installed) return 'xkeen'
    if (!s.subscription || !s.configured) return 'subscription'
    if (!s.routing_mode_configured) return 'routing'
    if (!s.policy_found) return 'devices'
    return 'start'
}

export function WelcomePage() {
    const navigate = useNavigate()
    const setup = useSetupState()
    const [step, setStep] = useState<StepId | null>(null)
    const s = setup.data

    useEffect(() => {
        if (s && step === null) setStep(firstStep(s))
    }, [s, step])

    const later = () => {
        try {
            sessionStorage.setItem(SETUP_LATER_KEY, '1')
        } catch {
            // Private mode can refuse storage; the redirect then simply asks again
        }
        navigate('/')
    }

    const index = step ? STEPS.indexOf(step) : -1

    return (
        <div className='flex min-h-dvh flex-col'>
            <div aria-hidden className='bg-page fixed inset-0 -z-10' />

            <header className='mx-auto flex w-full max-w-lg items-center justify-between px-5 pt-[max(16px,env(safe-area-inset-top))]'>
                <div className='flex items-center gap-2'>
                    <Logo size={26} />
                    <span className='text-[17px] font-semibold'>XKeen</span>
                </div>
                {s?.xkeen_installed && (
                    <button
                        type='button'
                        onClick={later}
                        className='min-h-11 cursor-pointer px-1 text-[17px] text-tint'
                    >
                        Позже
                    </button>
                )}
            </header>

            {index >= 0 && (
                <div
                    className='mx-auto mt-3 flex w-full max-w-lg gap-1.5 px-5'
                    aria-label={`Шаг ${index + 1} из ${STEPS.length}`}
                >
                    {STEPS.map((id, i) => (
                        <span
                            key={id}
                            className={cn(
                                'h-1 flex-1 rounded-full transition-colors duration-300',
                                i <= index ? 'bg-primary' : 'bg-white/12',
                            )}
                        />
                    ))}
                </div>
            )}

            <main
                key={step ?? 'loading'}
                className='mx-auto flex w-full max-w-lg flex-1 flex-col px-5 pb-[max(24px,env(safe-area-inset-bottom))] pt-8 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-right-4 motion-safe:duration-300'
            >
                {!s && (
                    <div className='flex flex-1 items-center justify-center'>
                        <IconLoader2 className='size-6 animate-spin text-muted-foreground' />
                    </div>
                )}
                {s && step === 'xkeen' && (
                    <XKeenStep onRetry={() => {
                        void setup.refetch().then(result => { if (result.data) setStep(firstStep(result.data)) })
                    }} />
                )}
                {s && step === 'subscription' && (
                    <SubscriptionStep
                        state={s}
                        onNext={() => setStep('routing')}
                    />
                )}
                {s && step === 'routing' && (
                    <>
                        <StepHeader icon={<IconTerminal2 className='size-8' />} color='#6366f1' title='Режим VPN'>
                            Выберите нужные сервисы или VPN для всего трафика. При миграции можно сохранить прежнюю политику.
                        </StepHeader>
                        <RoutingModeForm onApplied={() => setStep('devices')} />
                        <button type='button' onClick={() => setStep('subscription')} className='mt-4 min-h-11 text-tint'>Назад</button>
                    </>
                )}
                {s && step === 'devices' && (
                    <DevicesStep
                        state={s}
                        onBack={() => setStep('routing')}
                        onNext={() => setStep('start')}
                    />
                )}
                {s && step === 'start' && (
                    <StartStep state={s} onBack={() => setStep('devices')} />
                )}
            </main>
        </div>
    )
}

function StepHeader({
    icon,
    color,
    title,
    children,
}: {
    icon: ReactNode
    color: string
    title: string
    children: ReactNode
}) {
    return (
        <div className='mb-6 flex flex-col items-center text-center'>
            <span
                className='mb-4 flex size-16 items-center justify-center rounded-[18px] text-white'
                style={{ background: color }}
            >
                {icon}
            </span>
            <h1 className='text-[28px] font-bold leading-tight tracking-[-0.8px]'>
                {title}
            </h1>
            <p className='mt-2 text-[17px] leading-snug tracking-[-0.43px] text-muted-foreground'>
                {children}
            </p>
        </div>
    )
}

function Actions({
    primary,
    secondary,
}: {
    primary: {
        label: string
        onClick: () => void
        disabled?: boolean
        busy?: boolean
    }
    secondary?: { label: string; onClick: () => void }
}) {
    return (
        <div className='mt-auto flex flex-col gap-2 pt-8'>
            <button
                type='button'
                onClick={primary.onClick}
                disabled={primary.disabled || primary.busy}
                className='flex min-h-[52px] cursor-pointer items-center justify-center gap-2 rounded-2xl bg-primary text-[17px] font-semibold transition-opacity disabled:opacity-50'
            >
                {primary.busy && (
                    <IconLoader2 className='size-5 animate-spin' />
                )}
                {primary.label}
            </button>
            {secondary && (
                <button
                    type='button'
                    onClick={secondary.onClick}
                    className='min-h-11 cursor-pointer text-[17px] text-tint'
                >
                    {secondary.label}
                </button>
            )}
        </div>
    )
}

function XKeenStep({ onRetry }: { onRetry: () => void }) {
    return (
        <>
            <StepHeader
                icon={<IconTerminal2 className='size-8' stroke={2} />}
                color='#8e8e93'
                title='XKeen не установлен'
            >
                XKeen пока не обнаружен. Поручите установку агенту со скиллом
                «xkeen-router-install»: он проверит модель, память и прежние
                настройки, подготовит совместимую версию и сохранит возврат.
            </StepHeader>
            <Group
                footer='Потребуются доступ к роутеру в домашней сети и готовая подписка или ссылка сервера. Не отключайте VPN компьютера, пока агент не проверит альтернативный доступ.'
            >
                <a
                    href='https://github.com/Sgadmer/xkeen-panel/blob/v3.0.0-beta.1/docs/installation.md'
                    target='_blank'
                    rel='noopener noreferrer'
                    className='flex min-h-12 items-center py-3 text-[15px] text-tint'
                >
                    Порядок установки и скилл
                </a>
            </Group>
            <Actions primary={{ label: 'Проверить снова', onClick: onRetry }} />
        </>
    )
}

function SubscriptionStep({ state, onNext }: { state: SetupState; onNext: () => void }) {
    const [editing, setEditing] = useState(!state.subscription)
    const ready = state.subscription && state.configured && !editing
    return <>
        <StepHeader icon={<IconLink className='size-8' stroke={2} />} color='#6366f1' title='Серверы VPN'>
            Подписка провайдера, готовая ссылка собственного сервера или файл. Панель проверит реальное HTTPS-соединение.
        </StepHeader>
        {ready ? <Group>
            <Row icon={<IconCircleCheckFilled className='size-[22px] text-success' />} label='Серверы подключены' hint={`${state.servers} серверов${state.pool_nodes ? ` · в пуле ${state.pool_nodes}` : ''}`} />
            <Row label='Заменить источник' tone='tint' onClick={() => setEditing(true)} />
        </Group> : <Group><ServerSourceForm onApplied={() => setEditing(false)} /></Group>}
        {ready && <Actions primary={{ label: 'Далее: режим VPN', onClick: onNext }} />}
        {editing && state.subscription && <button type='button' onClick={() => setEditing(false)} className='mt-4 min-h-11 text-tint'>Отмена</button>}
    </>
}
function DevicesStep({
    state,
    onBack,
    onNext,
}: {
    state: SetupState
    onBack: () => void
    onNext: () => void
}) {
    const qc = useQueryClient()
    const devices = useDevices()
    const createPolicy = useMutation({
        mutationFn: () => api.post<SetupState>('/api/setup/policy'),
        onSuccess: data => {
            qc.setQueryData(['setup'], data)
            qc.invalidateQueries({ queryKey: ['devices'] })
        },
    })

    return (
        <>
            <StepHeader
                icon={<IconDeviceDesktop className='size-8' stroke={2} />}
                color='#30d158'
                title='Устройства'
            >
                {state.policy_found
                    ? 'Выберите, кто пойдёт через VPN. Остальные устройства будут работать напрямую.'
                    : 'Через VPN пойдут только выбранные устройства. Для этого на роутере нужна политика доступа xkeen — панель создаст её сама.'}
            </StepHeader>

            {!state.router_api && (
                <Group footer='Панель обращается к API роутера на 127.0.0.1:79. Если в xkeen.json задан rci_token, он должен быть верным.'>
                    <Row label='API роутера недоступен' tone='destructive' />
                </Group>
            )}

            {state.router_api && !state.policy_found && createPolicy.error && (
                <p className='px-4 text-[13px] text-destructive'>
                    {createPolicy.error.message}
                </p>
            )}

            {state.policy_found && devices.data && (
                <div className='flex flex-col gap-5'>
                    <NewDevicesGroup data={devices.data} />
                    <DeviceGroups data={devices.data} />
                </div>
            )}

            <Actions
                primary={
                    state.policy_found
                        ? { label: 'Далее', onClick: onNext }
                        : {
                              label: 'Создать политику',
                              onClick: () => createPolicy.mutate(),
                              disabled: !state.router_api,
                              busy: createPolicy.isPending,
                          }
                }
                secondary={{ label: 'Назад', onClick: onBack }}
            />
        </>
    )
}

function Check({ done, label }: { done: boolean; label: string }) {
    return (
        <Row
            icon={
                done ? (
                    <IconCircleCheckFilled className='size-[22px] text-success' />
                ) : (
                    <IconCircleDashed className='size-[22px] text-label-tertiary' />
                )
            }
            label={label}
        />
    )
}

function StartStep({
    state,
    onBack,
}: {
    state: SetupState
    onBack: () => void
}) {
    const qc = useQueryClient()
    const navigate = useNavigate()
    const [waitingSince, setWaitingSince] = useState<number | null>(null)
    const status = useStatus()
    const s = status.data

    const finish = useMutation({
        mutationFn: () => api.post<SetupState>('/api/setup/finish'),
        onSuccess: data => {
            qc.setQueryData(['setup'], data)
            setWaitingSince(Date.now())
        },
    })

    const verified =
        !!s?.connected &&
        !!s.proxy_checked &&
        (state.core_running || waitingSince !== null)
    const waiting = waitingSince !== null && !verified
    const timedOut = waiting && Date.now() - waitingSince > 90000

    useEffect(() => {
        if (!waiting) return
        const timer = setInterval(() => status.refetch(), 3000)
        return () => clearInterval(timer)
    }, [waiting, status])

    if (verified && (waitingSince !== null || state.complete)) {
        return (
            <>
                <StepHeader
                    icon={<IconCircleCheckFilled className='size-9' />}
                    color='#30d158'
                    title='Готово'
                >
                    VPN работает: связь проверена через выбранный сервер
                    {s?.latency_ms ? ` (${s.latency_ms} мс)` : ''}. Панель будет
                    следить за ним и сама заменит, если он упадёт.
                </StepHeader>
                <Actions
                    primary={{
                        label: 'Открыть панель',
                        onClick: () => navigate('/'),
                    }}
                />
            </>
        )
    }

    return (
        <>
            <StepHeader
                icon={<IconPlayerPlay className='size-8' stroke={2} />}
                color='#ff9f0a'
                title='Запуск'
            >
                Панель запустит XKeen, включит его автозапуск при старте роутера
                и проверит, что связь через VPN работает.
            </StepHeader>

            <Group
                footer={
                    finish.error ? (
                        <span className='text-destructive'>
                            {finish.error.message}
                        </span>
                    ) : timedOut ? (
                        <>
                            Связь через VPN пока не подтвердилась. Загляните в{' '}
                            <Link
                                to='/settings/diagnostics'
                                className='text-tint'
                            >
                                диагностику
                            </Link>{' '}
                            — там видно, что именно не работает.
                        </>
                    ) : undefined
                }
            >
                <Check done={state.core_running} label='XKeen запущен' />
                <Check
                    done={state.autostart}
                    label='Запускается вместе с роутером'
                />
                <Check
                    done={state.watchdog}
                    label='Упавший сервер меняется сам'
                />
                <Row
                    icon={
                        verified ? (
                            <IconCircleCheckFilled className='size-[22px] text-success' />
                        ) : waiting ? (
                            <IconLoader2 className='size-[22px] animate-spin text-tint' />
                        ) : (
                            <IconCircleDashed className='size-[22px] text-label-tertiary' />
                        )
                    }
                    label={
                        waiting
                            ? 'Проверяю связь через VPN…'
                            : 'Связь через VPN'
                    }
                />
            </Group>

            <Actions
                primary={{
                    label: waiting ? 'Проверяю…' : 'Запустить',
                    onClick: () => finish.mutate(),
                    busy: finish.isPending || waiting,
                }}
                secondary={{ label: 'Назад', onClick: onBack }}
            />
        </>
    )
}
