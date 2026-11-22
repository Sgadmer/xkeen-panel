import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { SetupPage } from '@/pages/setupPage'
import { LoginPage } from '@/pages/loginPage'
import { AppShell } from '@/components/appShell'
import { HomePage } from '@/pages/homePage'
import { ServersPage } from '@/pages/serversPage'
import { ServiceRoutesPage } from '@/pages/serviceRoutesPage'
import { DevicesPage } from '@/pages/devicesPage'
import { ExclusionsPage } from '@/pages/exclusionsPage'
import { JournalPage } from '@/pages/journalPage'
import { MorePage } from '@/pages/morePage'
import { SettingsPage } from '@/pages/settingsPage'
import { NotificationsPage } from '@/pages/notificationsPage'
import { UpdatePage } from '@/pages/updatePage'
import { DiagnosticsPage } from '@/pages/diagnosticsPage'
import { AccessPage } from '@/pages/accessPage'
import { ProtectionPage } from '@/pages/protectionPage'
import { AutomationPage } from '@/pages/automationPage'
import { SecurityPage } from '@/pages/securityPage'
import { TransferPage } from '@/pages/transferPage'
import { RecommendedPage } from '@/pages/recommendedPage'
import { ComponentsPage } from '@/pages/componentsPage'
import { WelcomePage } from '@/pages/welcomePage'
import { ProtectedRoute } from '@/components/protectedRoute'
import { moveToSecureAddress } from '@/lib/secureAddress'
import type { AuthStatus } from '@/types'

export function App() {
    const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetch('/api/auth/status')
            .then(r => r.json())
            .then(async (data: AuthStatus) => {
                // The page is being replaced: keep the loading screen until it is.
                if (await moveToSecureAddress(data)) return new Promise<never>(() => {})
                setAuthStatus(data)
            })
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
                            <Route path='services' element={<ServiceRoutesPage />} />
                            <Route path='devices' element={<DevicesPage />} />
                            <Route path='exclusions' element={<ExclusionsPage />} />
                            <Route path='journal' element={<JournalPage />} />
                            <Route path='more' element={<MorePage />} />
                            <Route path='settings' element={<SettingsPage />} />
                            <Route path='settings/notifications' element={<NotificationsPage />} />
                            <Route path='settings/access' element={<AccessPage />} />
                            <Route path='settings/protection' element={<ProtectionPage />} />
                            <Route path='settings/automation' element={<AutomationPage />} />
                            <Route path='settings/security' element={<SecurityPage />} />
                            <Route path='settings/transfer' element={<TransferPage />} />
                            <Route path='settings/recommended' element={<RecommendedPage />} />
                            <Route path='settings/routing' element={<Navigate to='/settings/protection' replace />} />
                            <Route path='settings/components' element={<ComponentsPage />} />
                            <Route
                                path='settings/update'
                                element={<UpdatePage />}
                            />
                            <Route path='settings/xkeen' element={<Navigate to='/exclusions' replace />} />
                            <Route
                                path='diagnostics'
                                element={<DiagnosticsPage />}
                            />
                            <Route path='settings/diagnostics' element={<Navigate to='/diagnostics' replace />} />
                        </Route>
                        <Route path='*' element={<Navigate to='/' />} />
                    </>
                )}
            </Routes>
        </BrowserRouter>
    )
}
