import { useEffect, useRef } from 'react'
import { Link, Navigate, Outlet, useLocation } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
    IconActivity,
    IconRouteOff,
    IconDeviceDesktop,
    IconDeviceDesktopFilled,
    IconDots,
    IconListSearch,
    IconLayoutGrid,
    IconLayoutGridFilled,
    IconLoader2,
    IconRefresh,
    IconSettings,
    IconSettingsFilled,
    IconShield,
    IconShieldFilled,
    IconWorld,
    type Icon,
} from '@tabler/icons-react'
import { Glass } from '@/components/glass'
import { useKillSwitch } from '@/components/killSwitch'
import { Logo } from '@/components/logo'
import { useEventSource } from '@/hooks/useEventSource'
import { useIndicator } from '@/hooks/useIndicator'
import { useStatus } from '@/hooks/usePanelData'
import { SETUP_LATER_KEY, useSetupState } from '@/pages/welcomePage'
import { statusInfo, toneDot, toneText } from '@/lib/format'
import { cn } from '@/lib/utils'
import { useGuardNotifications } from '@/lib/notifications'
import { refreshSession } from '@/lib/api'

type Tab = { to: string; label: string; icon: Icon; active: Icon }

// Every section, as the sidebar of a wide screen lists them.
export const SECTIONS: Tab[] = [
    { to: '/', label: 'Главная', icon: IconShield, active: IconShieldFilled },
    { to: '/servers', label: 'Серверы', icon: IconWorld, active: IconWorld },
    { to: '/services', label: 'Сервисы', icon: IconLayoutGrid, active: IconLayoutGridFilled },
    { to: '/journal', label: 'Журнал', icon: IconListSearch, active: IconListSearch },
    {
        to: '/devices',
        label: 'Устройства',
        icon: IconDeviceDesktop,
        active: IconDeviceDesktopFilled,
    },
    {
        to: '/exclusions',
        label: 'Исключения',
        icon: IconRouteOff,
        active: IconRouteOff,
    },
    {
        to: '/diagnostics',
        label: 'Диагностика',
        icon: IconActivity,
        active: IconActivity,
    },
    {
        to: '/settings',
        label: 'Настройки',
        icon: IconSettings,
        active: IconSettingsFilled,
    },
]

// A phone has room for five. The rest open from "Ещё".
const PRIMARY = ['/', '/services', '/servers', '/journal']
const MORE: Tab = { to: '/more', label: 'Ещё', icon: IconDots, active: IconDots }
const BAR: Tab[] = [...PRIMARY.map(to => SECTIONS.find(tab => tab.to === to)!), MORE]
export const MORE_SECTIONS = SECTIONS.filter(tab => !PRIMARY.includes(tab.to))

function tabIndex(tabs: Tab[], pathname: string) {
    if (pathname === '/') return 0
    return tabs.findIndex(t => t.to !== '/' && pathname.startsWith(t.to))
}

export function AppShell() {
    useEventSource()
    useGuardNotifications()
    useEffect(() => {
        void refreshSession()
        const timer = window.setInterval(() => void refreshSession(), 6 * 60 * 60 * 1000)
        return () => window.clearInterval(timer)
    }, [])
    const { pathname } = useLocation()
    const status = useStatus()
    const s = status.data
    const killSwitch = useKillSwitch(s?.core === 'mihomo').data?.enabled
    const info = statusInfo(s, killSwitch)
    const updated = usePanelUpdated(s?.panel_version)
    const active = tabIndex(SECTIONS, pathname)
    // On a phone a section that lives under "Ещё" lights that button.
    const direct = tabIndex(BAR, pathname)
    const barActive = direct >= 0 ? direct : active >= 0 ? BAR.length - 1 : -1

    const sidebarRef = useRef<HTMLElement>(null)
    const tabbarRef = useRef<HTMLElement>(null)
    const sidebarPill = useIndicator(sidebarRef, active)
    const tabbarPill = useIndicator(tabbarRef, barActive)

    const setup = useSetupState().data
    if (setup && !setup.subscription && !setupPostponed()) {
        return <Navigate to='/welcome' replace />
    }

    return (
        <div className='min-h-dvh lg:flex lg:gap-6 lg:p-3'>
            <div aria-hidden className='bg-page fixed inset-0 -z-20' />

            {(s?.restarting || updated) && (
                <div className='fixed inset-x-0 top-[max(10px,env(safe-area-inset-top))] z-30 flex justify-center px-4'>
                    <Glass className='flex items-center gap-3 rounded-full px-4 py-2 text-[15px]'>
                        {s?.restarting ? (
                            <>
                                <IconLoader2 className='size-4 animate-spin text-warning' />
                                XKeen перезапускается
                            </>
                        ) : (
                            <>
                                Панель обновлена до {s?.panel_version}
                                <button
                                    type='button'
                                    onClick={() => window.location.reload()}
                                    className='flex min-h-9 cursor-pointer items-center gap-1 font-semibold text-tint'
                                >
                                    <IconRefresh className='size-4' />
                                    Перезагрузить
                                </button>
                            </>
                        )}
                    </Glass>
                </div>
            )}

            <Glass className='sticky top-3 hidden h-[calc(100dvh-1.5rem)] w-60 shrink-0 flex-col gap-1 rounded-[22px] px-3 py-5 lg:flex'>
                <div className='flex items-center gap-2.5 px-2 pb-4'>
                    <Logo size={34} />
                    <div>
                        <div className='text-[15px] font-semibold tracking-[-0.24px]'>
                            XKeen
                        </div>
                        <div
                            className={cn(
                                'flex items-center gap-1.5 text-xs',
                                toneText[info.tone],
                            )}
                        >
                            <span
                                className={cn(
                                    'size-1.5 rounded-full',
                                    toneDot[info.tone],
                                )}
                            />
                            {info.label}
                        </div>
                        {info.detail && <div className='mt-0.5 max-w-48 text-xs leading-snug text-muted-foreground'>{info.detail}</div>}
                    </div>
                </div>
                <nav
                    ref={sidebarRef}
                    aria-label='Разделы'
                    className='relative flex flex-col gap-0.5'
                >
                    <span
                        aria-hidden
                        className='absolute left-0 top-0 rounded-xl bg-white/12'
                        style={sidebarPill}
                    />
                    {SECTIONS.map((tab, i) => (
                        <SidebarLink
                            key={tab.to}
                            {...tab}
                            current={i === active}
                        />
                    ))}
                </nav>
                <div className='flex-1' />
                <p className='px-3 pt-2 text-xs text-label-tertiary'>
                    Панель {s?.panel_version ?? '—'}
                    {s?.xkeen_version && ` · XKeen ${s.xkeen_version}`}
                </p>
            </Glass>

            <main className='mx-auto w-full max-w-5xl min-w-0 flex-1 px-4 pb-32 pt-[max(14px,env(safe-area-inset-top))] lg:px-4 lg:pb-10 lg:pt-6'>
                <div
                    key={pathname}
                    className='flex flex-col gap-5 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-2 motion-safe:duration-200'
                >
                    <Outlet />
                </div>
            </main>

            <div className='fixed inset-x-4 bottom-[max(16px,env(safe-area-inset-bottom))] z-20 max-[380px]:inset-x-1 lg:hidden'>
                <Glass className='rounded-full'>
                    <nav
                        ref={tabbarRef}
                        aria-label='Разделы'
                        className='relative grid h-16 grid-cols-5 p-1.5'
                    >
                        <span
                            aria-hidden
                            className='absolute left-0 top-0 rounded-full bg-white/12'
                            style={tabbarPill}
                        />
                        {BAR.map((tab, i) => {
                            const current = i === barActive
                            const TabIcon = current ? tab.active : tab.icon
                            return (
                                <Link
                                    key={tab.to}
                                    to={tab.to}
                                    data-tab
                                    aria-label={tab.label}
                                    aria-current={current ? 'page' : undefined}
                                    className={cn(
                                        'relative flex select-none flex-col items-center justify-center gap-0.5 rounded-full text-[11px] transition-[color,transform] duration-200 active:scale-[0.92]',
                                        current
                                            ? 'font-semibold text-tint'
                                            : 'font-medium text-muted-foreground',
                                    )}
                                >
                                    <TabIcon
                                        className='size-[22px]'
                                        stroke={current ? 2.2 : 1.8}
                                    />
                                    <span>{tab.label}</span>
                                </Link>
                            )
                        })}
                    </nav>
                </Glass>
            </div>
        </div>
    )
}

function SidebarLink({
    to,
    label,
    icon: TabIcon,
    active: ActiveIcon,
    current,
}: {
    to: string
    label: string
    icon: Icon
    active: Icon
    current: boolean
}) {
    const NavIcon = current ? ActiveIcon : TabIcon
    return (
        <Link
            to={to}
            data-tab
            aria-current={current ? 'page' : undefined}
            className={cn(
                'relative flex min-h-10 items-center gap-2.5 rounded-xl px-3 text-[15px] tracking-[-0.24px] transition-colors duration-200',
                current ? 'font-semibold text-tint' : 'hover:bg-white/6',
            )}
        >
            <NavIcon className='size-[18px]' stroke={1.9} />
            {label}
        </Link>
    )
}

function setupPostponed() {
    try {
        return sessionStorage.getItem(SETUP_LATER_KEY) === '1'
    } catch {
        return false
    }
}

// The open page keeps running the old bundle after the panel is replaced,
// whether it updated itself or a build was put on the router by hand. It
// reloads on its own; only someone in the middle of typing gets the button.
function usePanelUpdated(version?: string) {
    const qc = useQueryClient()
    const loaded = useRef<string | undefined>(undefined)
    if (version && !loaded.current) loaded.current = version
    const updated = !!version && version !== loaded.current

    useEffect(() => {
        if (version) qc.invalidateQueries({ queryKey: ['update'] })
    }, [version, qc])
    useEffect(() => {
        if (updated && !typing()) window.location.reload()
    }, [updated])

    return updated
}

function typing() {
    const focused = document.activeElement
    return (
        focused instanceof HTMLInputElement ||
        focused instanceof HTMLTextAreaElement ||
        focused instanceof HTMLSelectElement ||
        !!document.querySelector('[role="dialog"], [role="alertdialog"]')
    )
}
