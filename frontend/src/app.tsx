import { BrowserRouter, Routes, Route, Navigate, NavLink, Outlet } from 'react-router-dom'
import { Logo } from '@/components/logo'
import { useEffect, useState } from 'react'
import { SetupPage } from '@/pages/setupPage'
import { LoginPage } from '@/pages/loginPage'
import { AppShell } from '@/components/appShell'
import { HomePage } from '@/pages/homePage'
import { ServersPage } from '@/pages/serversPage'
import { ServiceRoutesPage, CardSubscriptionPage } from '@/pages/serviceRoutesPage'
import { DevicesPage } from '@/pages/devicesPage'
import { ExclusionsPage } from '@/pages/exclusionsPage'
import { SettingsPage } from '@/pages/settingsPage'
import { UpdatePage } from '@/pages/updatePage'
import { XkeenSettingsPage } from '@/pages/xkeenSettingsPage'
import { DiagnosticsPage } from '@/pages/diagnosticsPage'
import { AccessPage } from '@/pages/accessPage'
import { RoutingModePage } from '@/pages/routingModePage'
import { ComponentsPage } from '@/pages/componentsPage'
import { WelcomePage } from '@/pages/welcomePage'
import { ProtectedRoute } from '@/components/protectedRoute'
import type { AuthStatus } from '@/types'

export function App() {
    const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetch('/api/auth/status')
            .then(r => r.json())
            .then(data => setAuthStatus(data))
            .catch(() => setAuthStatus({ setup_required: false }))
            .finally(() => setLoading(false))
    }, [])

    if (loading) {
        return (
            <div className='min-h-screen flex items-center justify-center'>
                <div className='text-muted-foreground text-sm'>Загрузка...</div>
            </div>
        )
    }

    return (
        <BrowserRouter>
            <Routes>
                {authStatus?.cards_panel ? (
                    <>
                        <Route path='/login' element={<LoginPage />} />
                        <Route element={
                            <ProtectedRoute>
                                <main className='mx-auto flex min-h-dvh max-w-5xl flex-col gap-5 px-4 py-6'>
                                    <div aria-hidden className='bg-page fixed inset-0 -z-10' />
                                    <header className='flex flex-wrap items-center justify-between gap-3'>
                                        <div className='flex items-center gap-2 text-base font-semibold'><Logo size={30} /> XKeen Panel</div>
                                        <nav aria-label='Разделы' className='flex gap-1 rounded-full bg-card p-1'>
                                            {Object.entries({'/services':'Сервисы','/servers':'Серверы','/exclusions':'Исключения'}).map(([to,label]) =>
                                                <NavLink key={to} to={to} className={({isActive}) => 'rounded-full px-3 py-2 text-sm ' + (isActive ? 'bg-fill font-semibold text-tint' : 'text-muted-foreground')}>{label}</NavLink>)}
                                        </nav>
                                    </header>
                                    <Outlet />
                                </main>
                            </ProtectedRoute>
                        }>
                            <Route path='/services' element={<ServiceRoutesPage />} />
                            <Route path='/servers' element={<CardSubscriptionPage />} />
                            <Route path='/exclusions' element={<ExclusionsPage />} />
                        </Route>
                        <Route path='*' element={<Navigate to='/services' replace />} />
                    </>
                ) : authStatus?.setup_required ? (
                    <>
                        <Route path='/setup' element={<SetupPage />} />
                        <Route path='*' element={<Navigate to='/setup' />} />
                    </>
                ) : (
                    <>
                        <Route path='/login' element={<LoginPage />} />
                        <Route
                            path='/welcome'
                            element={
                                <ProtectedRoute>
                                    <WelcomePage />
                                </ProtectedRoute>
                            }
                        />
                        <Route
                            element={
                                <ProtectedRoute>
                                    <AppShell />
                                </ProtectedRoute>
                            }
                        >
                            <Route index element={<HomePage />} />
                            <Route path='servers' element={<ServersPage />} />
                            <Route path='services' element={<ServiceRoutesPage />} />
                            <Route path='devices' element={<DevicesPage />} />
                            <Route path='exclusions' element={<ExclusionsPage />} />
                            <Route path='settings' element={<SettingsPage />} />
                            <Route path='settings/access' element={<AccessPage />} />
                            <Route path='settings/routing' element={<RoutingModePage />} />
                            <Route path='settings/components' element={<ComponentsPage />} />
                            <Route
                                path='settings/update'
                                element={<UpdatePage />}
                            />
                            <Route
                                path='settings/xkeen'
                                element={<XkeenSettingsPage />}
                            />
                            <Route
                                path='settings/diagnostics'
                                element={<DiagnosticsPage />}
                            />
                        </Route>
                        <Route path='*' element={<Navigate to='/' />} />
                    </>
                )}
            </Routes>
        </BrowserRouter>
    )
}
