import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { SetupPage } from '@/pages/setupPage'
import { LoginPage } from '@/pages/loginPage'
import { AppShell } from '@/components/appShell'
import { HomePage } from '@/pages/homePage'
import { ServersPage } from '@/pages/serversPage'
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
                {authStatus?.setup_required ? (
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
