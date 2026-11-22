import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Group, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { api } from '@/lib/api'

type Core = {
    supported: boolean
    reason?: string
    installed?: string
    latest?: string
    checked_at?: string
    staged: boolean
    previous?: string
    busy: boolean
    phase?: string
    error?: string
}

const key = ['mihomo-core']
const path = '/api/components/mihomo'
const phases: Record<string, string> = { download: 'Скачиваем и сверяем контрольную сумму…', validate: 'Проверяем на этом роутере…', apply: 'Записываем на диск…' }

// The version of the core. A new binary is checked on this router and written
// to disk; the running core is not touched until XKeen is restarted.
export function MihomoCore() {
    const client = useQueryClient()
    const query = useQuery({ queryKey: key, queryFn: () => api.get<Core>(path), refetchInterval: q => q.state.data?.busy ? 2000 : 60000 })
    const store = (core: Core) => client.setQueryData(key, core)
    const check = useMutation({ mutationFn: () => api.post<Core>(path + '/check'), onSuccess: store })
    const install = useMutation({ mutationFn: (version: string) => api.post<Core>(path + '/install', { version }), onSuccess: core => { store(core); setAsking('') } })
    const rollback = useMutation({ mutationFn: () => api.post<Core>(path + '/rollback'), onSuccess: core => { store(core); setReturning(false) } })
    const [asking, setAsking] = useState('')
    const [returning, setReturning] = useState(false)
    const [picked, setPicked] = useState('')
    // The list of releases is asked for only when the picker is opened
    const [listing, setListing] = useState(false)
    const list = useQuery({ queryKey: ['mihomo-versions'], queryFn: () => api.get<{ versions: string[] }>(path + '/versions'), enabled: listing, staleTime: 15 * 60 * 1000, retry: false })
    const core = query.data
    if (!core) return <Group title='Версия Mihomo'><Row label={query.isPending ? 'Определяем версию…' : 'Не удалось определить версию'} /></Group>
    if (!core.supported) return <Group title='Версия Mihomo'><Row label='Управление версией недоступно' hint={core.reason} /></Group>

    const newer = !!core.latest && !!core.installed && core.latest !== core.installed
    const versions = list.data?.versions ?? []
    const wanted = versions.includes(picked) ? picked : (versions.find(version => version !== core.installed) ?? '')
    const error = check.error?.message || core.error
    return <Group title='Версия Mihomo' footer='Панель скачивает официальный выпуск, сверяет его контрольную сумму, запускает на этом роутере и проверяет им текущую конфигурацию. Прежняя версия остаётся рядом для возврата.'>
        <Row label='Установлена' detail={core.installed || 'не определена'}
            hint={core.staged ? undefined : core.checked_at && core.latest ? (newer ? 'Доступна ' + core.latest : 'Это последняя стабильная версия') : undefined} />
        {core.staged && <p role='status' className='py-3 text-[13px] leading-relaxed text-warning'>
            Новая версия записана на диск, но ядро ещё работает на прежней. Она начнёт работать после перезапуска XKeen — в разделе{' '}
            <Link to='/diagnostics' className='underline'>«Диагностика»</Link> — или после перезагрузки роутера.
        </p>}
        {core.busy
            ? <Row label={phases[core.phase ?? ''] ?? 'Выполняем…'} />
            : <>
                <Row label={check.isPending ? 'Проверяем…' : 'Проверить обновление'} tone='tint' disabled={check.isPending} onClick={() => check.mutate()} />
                {newer && <Row label={'Установить ' + core.latest} tone='tint' onClick={() => { install.reset(); setAsking(core.latest!) }} />}
                {core.previous && <Row label={'Вернуть ' + core.previous} tone='tint' onClick={() => { rollback.reset(); setReturning(true) }} />}
                <details className='py-2 text-sm' onToggle={event => { if (event.currentTarget.open) setListing(true) }}>
                    <summary className='min-h-9 cursor-pointer text-muted-foreground'>Другая версия</summary>
                    {list.isFetching ? <p className='pb-2 text-muted-foreground'>Загружаем список версий…</p>
                        : list.error ? <div className='flex flex-wrap items-center gap-3 pb-2'>
                            <p role='alert' className='text-destructive'>Список версий не загружен: {list.error.message}</p>
                            <button type='button' onClick={() => list.refetch()} className='min-h-11 cursor-pointer rounded-xl bg-fill px-3 text-[15px] text-tint'>Повторить</button>
                        </div>
                        : versions.length === 0 ? <p className='pb-2 text-muted-foreground'>Подходящих версий не найдено.</p>
                        : <div className='flex flex-wrap items-center gap-2 pb-2'>
                            <select aria-label='Версия Mihomo' value={wanted} onChange={event => setPicked(event.target.value)}
                                className='min-h-11 w-48 rounded-xl border border-white/10 bg-fill px-3 text-[16px] outline-none focus:border-tint'>
                                {versions.map(version => <option key={version} value={version} disabled={version === core.installed}>{version}{version === core.installed ? ' · установлена' : ''}</option>)}
                            </select>
                            <button type='button' disabled={!wanted || wanted === core.installed}
                                onClick={() => { install.reset(); setAsking(wanted) }} className='min-h-11 cursor-pointer rounded-xl bg-fill px-3 text-[15px] text-tint disabled:cursor-default disabled:opacity-50'>Установить</button>
                        </div>}
                </details>
            </>}
        {error && <p role='alert' className='py-3 text-sm text-destructive'>{error}</p>}
        {asking && <ProtectionWarning title={'Установить Mihomo ' + asking + '?'} confirmLabel='Установить' busy={install.isPending} error={install.error?.message}
            onCancel={() => { if (!install.isPending) setAsking('') }} onConfirm={() => install.mutate(asking)}>
            <p>Панель скачает выпуск, проверит его и заменит файл ядра на диске. <strong className='text-foreground'>Работающее ядро не прерывается</strong>: новая версия начнёт работать после перезапуска XKeen или роутера.</p>
            <p className='rounded-xl bg-warning/10 p-3 text-warning'>Ядро — то, через что идёт весь VPN. Если новая версия после перезапуска поведёт себя иначе, верните прежнюю кнопкой «Вернуть» здесь же и перезапустите XKeen ещё раз.</p>
        </ProtectionWarning>}
        {returning && core.previous && <ProtectionWarning title={'Вернуть Mihomo ' + core.previous + '?'} confirmLabel='Вернуть' delay={0} busy={rollback.isPending} error={rollback.error?.message}
            onCancel={() => { if (!rollback.isPending) setReturning(false) }} onConfirm={() => rollback.mutate()}>
            <p>Прежняя версия вернётся на диск после той же проверки. Она начнёт работать после перезапуска XKeen или роутера.</p>
        </ProtectionWarning>}
    </Group>
}
