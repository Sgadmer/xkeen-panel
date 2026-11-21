import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useLocation } from 'react-router-dom'
import { IconLoader2 } from '@tabler/icons-react'
import { RefilterBase } from '@/components/blocklistRouting'
import { Group, PageTitle, Row, Switch } from '@/components/ios'
import { MihomoCore } from '@/components/mihomoCore'
import { MihomoDns } from '@/components/mihomoDns'
import { ServiceListsProtection } from '@/components/serviceListsProtection'
import { SettingChangeDialog, type SettingChange } from '@/components/settingChangeDialog'
import { api } from '@/lib/api'

interface Release { tag_name: string; name: string; prerelease: boolean; published_at: string }
interface GeoSource { id: string; name: string; kind: string; repository: string; filename: string }
interface GeoSettings { sources: string[]; auto: boolean; day: number; hour: number; minute: number; last_attempt?: string }
interface Setting { id: string; name: string; hint: string; enabled: boolean; supported: boolean }
interface Job { id: string; component: string; version: string; phase: string; started: string; finished?: string; error?: string; backup_id?: string; rolled_back: boolean }
interface Backup { id: string; component: string; version: string; created: string; setting?: string }
interface ComponentsState {
    supported: boolean; settings_supported?: boolean; reason?: string; architecture: string; xkeen_version: string; xray_version: string
    mode: string; core: string; router_time: string; geodata: GeoSettings; sources: GeoSource[]
    job?: Job; backups: Backup[]; notes: string[]; settings: Setting[]
}
interface Preview {
    id: string; component: string; version: string; expires: string; warnings: string[]; required_bytes: number
    artifacts: { name: string; sha256: string; size: number; repository: string; version: string }[]
    change?: SettingChange
}
interface SettingIntent { setting: Setting; desired: boolean; sequence: number }
interface PendingSetting { setting: Setting; current: boolean; desired: boolean; job: Job }

const field = 'min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none focus:border-tint disabled:opacity-50'
const button = 'min-h-11 cursor-pointer rounded-xl bg-primary px-4 text-[15px] font-semibold text-primary-foreground disabled:cursor-default disabled:opacity-50'
const phases: Record<string, string> = {
    queued: 'Операция в очереди', download: 'Загружаем и проверяем файлы', validate: 'Проверяем совместимость',
    apply: 'Применяем изменения', restart: 'Восстанавливаем соединение и выбранный сервер', rollback: 'Восстанавливаем резервную копию', complete: 'Готово', failed: 'Операция не выполнена',
    recovering: 'Восстанавливаем состояние после прерванной операции',
}
const componentNames: Record<string, string> = { xkeen: 'XKeen', xray: 'Xray', geodata: 'Геобазы', settings: 'Параметр XKeen' }
const componentName = (component: string) => componentNames[component] || 'Компонент'

export function ComponentsPage() {
    const qc = useQueryClient()
    const query = useQuery({ queryKey: ['components'], queryFn: () => api.get<ComponentsState>('/api/components'), refetchInterval: q => q.state.data?.job && !q.state.data.job.finished ? 2000 : 30000 })
    const [preview, setPreview] = useState<Preview | null>(null)
    const [geoDraft, setGeoDraft] = useState<GeoSettings | null>(null)
    const geo = geoDraft ?? query.data?.geodata
    const [notice, setNotice] = useState('')
    const [settingIntent, setSettingIntent] = useState<SettingIntent | null>(null)
    const [pendingSetting, setPendingSetting] = useState<PendingSetting | null>(null)
    const settingSequence = useRef(0)
    const check = useMutation({
        mutationFn: (request: object) => api.post<Preview>('/api/components/preview', request),
        onSuccess: p => { setPreview(p); setNotice('') },
    })
    const apply = useMutation({
        mutationFn: (id: string) => api.post<Job>('/api/components/apply', { plan_id: id }),
        onSuccess: () => { setPreview(null); setNotice('Операция запущена. Дождитесь результата на этой странице.'); qc.invalidateQueries({ queryKey: ['components'] }) },
    })
    const settingCheck = useQuery({
        queryKey: ['setting-preview', settingIntent?.sequence],
        queryFn: () => api.post<Preview>('/api/components/preview', { component: 'settings', setting: settingIntent!.setting.id, enabled: settingIntent!.desired }),
        enabled: settingIntent !== null,
        retry: false,
        staleTime: Infinity,
        gcTime: 0,
    })
    const settingApply = useMutation({
        mutationFn: ({ id }: { id: string; setting: Setting; current: boolean; desired: boolean }) => api.post<Job>('/api/components/apply', { plan_id: id }),
        onSuccess: (job, request) => {
            setPendingSetting({ setting: request.setting, current: request.current, desired: request.desired, job })
            setSettingIntent(null)
            setNotice('')
            qc.setQueryData<ComponentsState>(['components'], old => old && { ...old, job })
            qc.invalidateQueries({ queryKey: ['components'] })
        },
    })
    const rollback = useMutation({
        mutationFn: (id: string) => api.post<Job>('/api/components/rollback', { backup_id: id }),
        onSuccess: () => { setNotice('Восстанавливаем резервную копию.'); qc.invalidateQueries({ queryKey: ['components'] }) },
    })
    const saveGeo = useMutation({
        mutationFn: (draft: GeoSettings) => api.put<ComponentsState>('/api/components/geodata', draft),
        onSuccess: data => { qc.setQueryData(['components'], data); setGeoDraft(null); setNotice('Источники и расписание сохранены. Для первой загрузки нажмите «Проверить обновление геобаз».') },
    })
    const state = query.data
    const { hash } = useLocation()
    const loaded = !!state
    // A link from a service card lands on the lists it speaks about.
    useEffect(() => {
        if (loaded && hash === '#service-lists') document.getElementById('service-lists')?.scrollIntoView()
    }, [loaded, hash])
    const busy = !!state?.job && !state.job.finished
    const working = busy || check.isPending || apply.isPending || rollback.isPending || saveGeo.isPending || settingApply.isPending || pendingSetting !== null
    const disabled = !state?.supported || working
    const canEditSettings = state?.settings_supported ?? state?.supported
    const visibleSettings = state?.settings.filter(setting => state.core !== 'mihomo' || (setting.id !== 'dns' && setting.id !== 'router_proxy')) ?? []
    const error = check.error ?? apply.error ?? saveGeo.error ?? rollback.error
    const settingPreview = settingCheck.data
    const settingReady = !!settingIntent && !!settingPreview?.id && settingPreview.component === 'settings' && settingPreview.change?.setting_id === settingIntent.setting.id && settingPreview.change.desired === settingIntent.desired && Date.parse(settingPreview.expires) > Date.now()
    const settingError = settingApply.error?.message ?? settingCheck.error?.message ?? (settingPreview && !settingReady ? 'Не удалось подтвердить подробности изменения. Повторите проверку.' : undefined)
    useEffect(() => {
        if (!pendingSetting || !state?.job) return
        if (state.job.id !== pendingSetting.job.id) {
            if (Date.parse(state.job.started) > Date.parse(pendingSetting.job.started)) {
                setPendingSetting(null)
                setNotice('На роутере началась следующая операция. Текущие значения показаны в списке настроек.')
            }
            return
        }
        if (!state.job.finished) return
        setPendingSetting(null)
        qc.invalidateQueries({ queryKey: ['components'] })
        const actual = state.settings.find(setting => setting.id === pendingSetting.setting.id)
        const confirmed = !state.job.error && !state.job.rolled_back && actual?.enabled === pendingSetting.desired
        setNotice(confirmed
            ? `«${pendingSetting.setting.name}» — ${actual.enabled ? 'включено' : 'выключено'}.`
            : `Роутер не подтвердил изменение «${pendingSetting.setting.name}». Подробности — в разделе «Последняя операция».`)
    }, [state, pendingSetting, qc])
    function inspect(request: object) { apply.reset(); rollback.reset(); check.reset(); setPreview(null); check.mutate(request) }
    function changeGeo(next: GeoSettings) { setGeoDraft(next); setPreview(null); setNotice('') }
    function inspectSetting(setting: Setting, desired: boolean) {
        settingApply.reset()
        setPreview(null)
        setNotice('')
        setSettingIntent({ setting, desired, sequence: ++settingSequence.current })
    }
    function closeSetting() { if (!settingApply.isPending) setSettingIntent(null) }
    function retrySetting() {
        settingApply.reset()
        if (settingIntent) setSettingIntent({ ...settingIntent, sequence: ++settingSequence.current })
    }

    return <>
        <PageTitle title='Роутер и XKeen' subtitle='Версии, списки адресов, порты' back={{ to: '/settings', label: 'Настройки' }} />
        {query.isPending ? <p className='px-4 text-muted-foreground'>Проверяем установку…</p> : query.error ? <p role='alert' className='px-4 text-destructive'>{query.error.message}</p> : null}
        {state && <>
            <Group title='Установлено' footer={state.core === 'mihomo' ? 'Выбор версий XKeen и Xray доступен при активном ядре Xray.' : state.reason}>
                <Row label='XKeen' detail={state.xkeen_version || 'Не определена'} />
                {state.core === 'xray' ? <Row label='Xray' detail={state.xray_version || 'Не определена'} />
                    : <Row label='Активное ядро' detail={state.core === 'mihomo' ? 'Mihomo' : state.core || 'Не определено'} />}
                <Row label='Архитектура' detail={state.architecture} />
                <Row label='Режим перехвата' detail={state.mode || 'Определяется XKeen'} hint='Режим зависит от доступных модулей ядра и конфигурации входов. Режим маршрутизации VPN настраивается отдельно.' />
            </Group>
            {state.job && <Group title='Последняя операция'>
                <div role='status' aria-live='polite' className='flex items-start gap-3 py-4'>
                    {busy && <IconLoader2 className='mt-0.5 size-5 shrink-0 animate-spin text-tint' />}
                    <div><p className='font-medium'>{phases[state.job.phase] || 'Выполняем операцию'}</p><p className='mt-1 text-[13px] text-muted-foreground'>{componentName(state.job.component)} · {state.job.version}</p>
                        {state.job.error && <p role='alert' className='mt-2 text-[14px] text-destructive'>{state.job.error}</p>}
                        {state.job.rolled_back && <p className='mt-1 text-[13px] text-muted-foreground'>Предыдущее состояние восстановлено.</p>}
                    </div>
                </div>
            </Group>}
            {state.core === 'mihomo' && <div className='grid grid-cols-1 gap-5 xl:grid-cols-2 xl:items-start'>
                <div className='flex min-w-0 flex-col gap-5'>
                    <div id='service-lists' className='scroll-mt-4'><ServiceListsProtection /></div>
                    <MihomoCore />
                </div>
                <div className='flex min-w-0 flex-col gap-5'>
                    <RefilterBase />
                    <MihomoDns />
                </div>
            </div>}
            {state.supported && <div className='grid grid-cols-1 gap-5 xl:grid-cols-2'>
                <VersionChoice component='xkeen' title='Версия XKeen' disabled={disabled} onPreview={inspect} />
                <VersionChoice component='xray' title='Версия Xray' disabled={disabled} onPreview={inspect} />
            </div>}
            {state.supported && geo && <Group title='Источники геобаз' footer='GeoIPSET исключает российские IP из VPN до проверки доменных правил Xray.'>
                {state.sources.map(source => <label key={source.id} className='flex min-h-11 cursor-pointer items-center justify-between gap-3 py-2'>
                    <span><span className='text-[15px]'>{source.kind} · {source.name}</span><span className='block text-[12px] text-muted-foreground'>{source.repository}</span></span>
                    <input type='checkbox' checked={geo.sources.includes(source.id)} disabled={disabled} onChange={event => changeGeo({ ...geo, sources: event.target.checked ? [...geo.sources, source.id] : geo.sources.filter(id => id !== source.id) })} className='size-5 shrink-0 accent-violet-500' />
                </label>)}
            </Group>}
            {state.supported && geo && <Group title='Обновление выбранных геобаз' footer={`Расписание использует время роутера: ${new Date(state.router_time).toLocaleString('ru-RU')}. При ошибке рабочие базы сохраняются.`}>
                <Row label='Обновлять автоматически' trailing={<Switch label='Обновлять автоматически' checked={geo.auto} disabled={disabled} onChange={auto => changeGeo({ ...geo, auto })} />} />
                <div className='space-y-4 py-4'>
                    <div className='grid grid-cols-3 gap-3'>
                        <label className='text-[13px] text-muted-foreground'>День<select aria-label='День обновления геобаз' className={field} value={geo.day} disabled={disabled} onChange={e => changeGeo({ ...geo, day: Number(e.target.value) })}>{['Ежедневно', 'Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота'].map((day, i) => <option key={day} value={i - 1}>{day}</option>)}</select></label>
                        <label className='text-[13px] text-muted-foreground'>Час<input aria-label='Час обновления' type='number' min={0} max={23} className={field} value={geo.hour} disabled={disabled} onChange={e => changeGeo({ ...geo, hour: Number(e.target.value) })} /></label>
                        <label className='text-[13px] text-muted-foreground'>Минута<input aria-label='Минута обновления' type='number' min={0} max={59} className={field} value={geo.minute} disabled={disabled} onChange={e => changeGeo({ ...geo, minute: Number(e.target.value) })} /></label>
                    </div>
                    <button className={`${button} w-full`} disabled={disabled || !geoDraft} onClick={() => saveGeo.mutate(geo)}>Сохранить источники и расписание</button>
                    <button className={`${button} w-full`} disabled={disabled || !!geoDraft || geo.sources.length === 0} onClick={() => inspect({ component: 'geodata' })}>Проверить обновление геобаз</button>
                </div>
            </Group>}
            <Group title='Параметры XKeen'>
                {visibleSettings.map(setting => {
                    const checked = pendingSetting?.setting.id === setting.id ? pendingSetting.current : setting.enabled
                    const isSchedule = setting.id === 'native_geodata_schedule'
                    const nativeOff = isSchedule && !checked
                    const hint = pendingSetting?.setting.id === setting.id ? 'Применяем изменение…' : setting.hint
                    if (!canEditSettings || !setting.supported || nativeOff) {
                        return <Row key={setting.id} label={setting.name} hint={hint} detail={setting.supported || nativeOff ? (checked ? 'Включено' : 'Выключено') : 'Недоступно'} />
                    }
                    if (isSchedule) return <div key={setting.id} className='flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between'>
                        <div><p className='text-[17px]'>{setting.name}</p><p className='mt-0.5 text-[13px] leading-snug text-muted-foreground'>{hint}</p></div>
                        <button type='button' onClick={() => inspectSetting(setting, false)} disabled={working}
                            className='min-h-11 shrink-0 self-start rounded-xl bg-fill px-3 text-[15px] font-medium text-tint disabled:opacity-50 sm:self-center'>Отключить расписание</button>
                    </div>
                    return <Row key={setting.id} label={setting.name} hint={hint} trailing={<span className='rounded-full focus-within:outline-2 focus-within:outline-offset-4 focus-within:outline-tint'><Switch checked={checked} label={setting.name} onChange={desired => inspectSetting(setting, desired)} disabled={working} /></span>} />
                })}
            </Group>
            <Group title='Дополнительно'>
                <Row label='Порты и IP-исключения XKeen' hint='Выберите, какие порты обрабатывать и какие IP-адреса пропускать напрямую.' to='/settings/xkeen' />
            </Group>
            {state.supported && preview && <Group title='Проверка перед применением'>
                <div className='space-y-3 py-4'>
                    <p className='font-semibold'>{componentName(preview.component)} · {preview.version}</p>
                    {preview.artifacts.map(a => <p key={a.name} className='break-all text-[13px] text-muted-foreground'>{a.repository} · {a.name} · {(a.size / 1048576).toFixed(1)} МБ<br />SHA-256: {a.sha256}</p>)}
                    <p className='text-[13px] text-muted-foreground'>Проверено место для загрузки, резервной копии и отката: нужно не менее {Math.ceil(preview.required_bytes / 1048576)} МБ.</p>
                    {preview.warnings.map(warning => <p key={warning} className='text-[14px] text-amber-300'>{warning}</p>)}
                    <button className={`${button} w-full`} disabled={disabled} onClick={() => apply.mutate(preview.id)}>Применить с резервной копией</button>
                    <button className='min-h-11 w-full text-[15px] text-muted-foreground' disabled={busy} onClick={() => setPreview(null)}>Отменить</button>
                </div>
            </Group>}
            {check.isPending && <p role='status' className='px-4 text-muted-foreground'>Получаем релиз, проверяем контрольные суммы и место…</p>}
            {error && <p role='alert' className='px-4 text-destructive'>{error.message}</p>}
            {notice && <p role='status' className='px-4 text-tint'>{notice}</p>}
            {state.backups.length > 0 && <Group title='Резервные копии компонентов'>
                {state.backups.map(backup => (backup.setting ? state.core === 'mihomo' && canEditSettings : state.supported) ? <BackupRow key={backup.id} backup={backup} disabled={working} onRollback={id => rollback.mutate(id)} />
                    : <Row key={backup.id} label={`${componentName(backup.component)} · ${backup.version}`} detail={new Date(backup.created).toLocaleDateString('ru-RU')} />)}
            </Group>}
            <p className='px-4 text-[13px] text-muted-foreground'>Обновления кода панели находятся в разделе <Link className='text-tint' to='/settings/update'>«О панели и обновление»</Link>. Подписка обновляется независимо от компонентов.</p>
        </>}
        {canEditSettings && settingIntent && <SettingChangeDialog
            name={settingIntent.setting.name}
            current={settingIntent.setting.enabled}
            desired={settingIntent.desired}
            change={settingReady ? settingPreview?.change : undefined}
            warnings={settingPreview?.warnings ?? []}
            requiredBytes={settingReady ? settingPreview?.required_bytes : undefined}
            loading={settingCheck.isFetching}
            error={settingError}
            applying={settingApply.isPending}
            ready={settingReady && !busy}
            onRetry={retrySetting}
            onCancel={closeSetting}
            onConfirm={() => {
                if (settingReady && settingPreview?.change && !busy) settingApply.mutate({ id: settingPreview.id, setting: settingIntent.setting, current: settingPreview.change.current, desired: settingPreview.change.desired })
            }}
        />}
    </>
}

function VersionChoice({ component, title, disabled, onPreview }: { component: string; title: string; disabled: boolean; onPreview: (request: object) => void }) {
    const [channel, setChannel] = useState('stable')
    const [version, setVersion] = useState('')
    const [load, setLoad] = useState(false)
    const releases = useQuery({ queryKey: ['component-releases', component, channel], queryFn: () => api.get<{ releases: Release[] }>(`/api/components/releases?component=${component}&channel=${channel}`), enabled: load })
    return <Group title={title} footer={component === 'xkeen' ? 'Доступны опубликованные релизы с проверяемой контрольной суммой. Непроверяемая Dev-сборка не устанавливается.' : 'Точная версия проверяется на роутере до замены работающего ядра.'}>
        <div className='space-y-3 py-4'>
            <label className='block text-[13px] text-muted-foreground'>Канал<select aria-label={`Канал ${component}`} className={field} value={channel} disabled={disabled} onChange={e => { setChannel(e.target.value); setVersion(''); setLoad(true) }}><option value='stable'>Стабильные</option><option value='prerelease'>Предварительные / Beta</option><option value='all'>Все опубликованные</option></select></label>
            <button className='min-h-11 text-[15px] text-tint disabled:opacity-50' disabled={disabled || releases.isFetching} onClick={() => { setLoad(true); if (load) releases.refetch() }}>{releases.isFetching ? 'Получаем версии…' : 'Загрузить список версий'}</button>
            {releases.data && <select aria-label={`Доступные версии ${component}`} className={field} value={version} disabled={disabled} onChange={e => setVersion(e.target.value)}><option value=''>Выберите версию</option>{releases.data.releases.map(r => <option key={r.tag_name} value={r.tag_name}>{r.tag_name}{r.prerelease ? ' · предварительная' : ''}</option>)}</select>}
            {releases.data?.releases.length === 0 && <p className='text-[13px] text-muted-foreground'>В этом канале пока нет опубликованных версий. Выберите другой канал или укажите точный тег.</p>}
            {releases.error && <p className='text-[13px] text-destructive'>{releases.error.message}</p>}
            <label className='block text-[13px] text-muted-foreground'>Или точный номер релиза<input aria-label={`Номер версии ${component}`} className={field} value={version} disabled={disabled} maxLength={80} placeholder={component === 'xray' ? 'v26.3.27' : '2.1'} onChange={e => setVersion(e.target.value)} /></label>
            <button className={`${button} w-full`} disabled={disabled || !version.trim()} onClick={() => onPreview({ component, version: version.trim() })}>Проверить выбранную версию</button>
        </div>
    </Group>
}

function BackupRow({ backup, disabled, onRollback }: { backup: Backup; disabled: boolean; onRollback: (id: string) => void }) {
    const [confirm, setConfirm] = useState(false)
    return <div className='space-y-2 py-3'><Row label={`${componentName(backup.component)} · ${backup.version}`} hint={new Date(backup.created).toLocaleString('ru-RU')} detail='Восстановить' onClick={() => setConfirm(v => !v)} disabled={disabled} />{confirm && <><p className='text-[13px] text-muted-foreground'>{backup.setting ? 'Вернуть значение этого параметра из копии?' : 'Восстановить состояние установки из этой копии? VPN кратко перезапустится.'}</p><button className={`${button} w-full`} disabled={disabled} onClick={() => { onRollback(backup.id); setConfirm(false) }}>Подтвердить восстановление</button></>}</div>
}
