import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { IconLoader2 } from '@tabler/icons-react'
import { Group, PageTitle, Row, Switch } from '@/components/ios'
import { SettingChangeDialog, type SettingChange } from '@/components/settingChangeDialog'
import { api } from '@/lib/api'

interface Release { tag_name: string; name: string; prerelease: boolean; published_at: string }
interface GeoSource { id: string; name: string; kind: string; repository: string; filename: string }
interface GeoSettings { sources: string[]; auto: boolean; day: number; hour: number; minute: number; last_attempt?: string }
interface Setting { id: string; name: string; hint: string; enabled: boolean; supported: boolean }
interface Job { id: string; component: string; version: string; phase: string; finished?: string; error?: string; backup_id?: string; rolled_back: boolean }
interface Backup { id: string; component: string; version: string; created: string }
interface ComponentsState {
    supported: boolean; reason?: string; architecture: string; xkeen_version: string; xray_version: string
    mode: string; core: string; router_time: string; geodata: GeoSettings; sources: GeoSource[]
    job?: Job; backups: Backup[]; notes: string[]; settings: Setting[]
}
interface Preview {
    id: string; component: string; version: string; expires: string; warnings: string[]; required_bytes: number
    artifacts: { name: string; sha256: string; size: number; repository: string; version: string }[]
    change?: SettingChange
}
interface SettingIntent { setting: Setting; desired: boolean; sequence: number }
interface PendingSetting { setting: Setting; current: boolean; jobId: string }

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
    const [geo, setGeo] = useState<GeoSettings>({ sources: [], auto: false, day: -1, hour: 4, minute: 0 })
    const [dirty, setDirty] = useState(false)
    const [notice, setNotice] = useState('')
    const [settingIntent, setSettingIntent] = useState<SettingIntent | null>(null)
    const [pendingSetting, setPendingSetting] = useState<PendingSetting | null>(null)
    const settingSequence = useRef(0)
    useEffect(() => { if (query.data && !dirty) setGeo(query.data.geodata) }, [query.data, dirty])
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
        mutationFn: ({ id }: { id: string; setting: Setting; current: boolean }) => api.post<Job>('/api/components/apply', { plan_id: id }),
        onSuccess: (job, request) => {
            setPendingSetting({ setting: request.setting, current: request.current, jobId: job.id })
            setSettingIntent(null)
            setNotice('Изменение запущено. Переключатель обновится после успешного завершения операции.')
            qc.invalidateQueries({ queryKey: ['components'] })
        },
    })
    const rollback = useMutation({
        mutationFn: (id: string) => api.post<Job>('/api/components/rollback', { backup_id: id }),
        onSuccess: () => { setNotice('Восстанавливаем резервную копию.'); qc.invalidateQueries({ queryKey: ['components'] }) },
    })
    const saveGeo = useMutation({
        mutationFn: () => api.put<ComponentsState>('/api/components/geodata', geo),
        onSuccess: data => { qc.setQueryData(['components'], data); setDirty(false); setNotice('Источники и расписание сохранены. Для первой загрузки нажмите «Проверить обновление геобаз».') },
    })
    const state = query.data
    const busy = !!state?.job && !state.job.finished
    const disabled = !state?.supported || busy || check.isPending || apply.isPending || rollback.isPending || saveGeo.isPending || settingApply.isPending || pendingSetting !== null
    const error = check.error ?? apply.error ?? saveGeo.error ?? rollback.error
    const settingPreview = settingCheck.data
    const settingReady = !!settingIntent && !!settingPreview?.id && settingPreview.component === 'settings' && settingPreview.change?.setting_id === settingIntent.setting.id && settingPreview.change.desired === settingIntent.desired && Date.parse(settingPreview.expires) > Date.now()
    const settingError = settingApply.error?.message ?? settingCheck.error?.message ?? (settingPreview && !settingReady ? 'Не удалось подтвердить подробности изменения. Повторите проверку.' : undefined)
    useEffect(() => {
        if (!pendingSetting || state?.job?.id !== pendingSetting.jobId || !state.job.finished) return
        setPendingSetting(null)
        qc.invalidateQueries({ queryKey: ['components'] })
        const actual = state.settings.find(setting => setting.id === pendingSetting.setting.id)
        setNotice(state.job.error || state.job.rolled_back
            ? `Изменение параметра «${pendingSetting.setting.name}» не выполнено. Проверьте результат последней операции.`
            : `Параметр «${pendingSetting.setting.name}»: ${actual?.enabled ? 'включено' : 'выключено'}.`)
    }, [state, pendingSetting, qc])
    function inspect(request: object) { apply.reset(); rollback.reset(); check.reset(); setPreview(null); check.mutate(request) }
    function changeGeo(next: GeoSettings) { setGeo(next); setDirty(true); setPreview(null); setNotice('') }
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
        <PageTitle title='Компоненты и геобазы' back={{ to: '/settings', label: 'Настройки' }} subtitle='Версии XKeen и Xray, источники геоданных и безопасное применение изменений.' />
        {query.isPending ? <p className='px-4 text-muted-foreground'>Проверяем установку…</p> : query.error ? <p role='alert' className='px-4 text-destructive'>{query.error.message}</p> : null}
        {state && <>
            <Group title='Установлено' footer={state.reason || 'Рекомендуемый выбор — стабильный совместимый релиз. Предварительные версии предназначены для тестирования.'}>
                <Row label='XKeen' detail={state.xkeen_version || 'Не определена'} />
                <Row label='Xray' detail={state.xray_version || 'Не определена'} />
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
            <div className='grid grid-cols-1 gap-5 xl:grid-cols-2'>
                <VersionChoice component='xkeen' title='Версия XKeen' disabled={disabled} onPreview={inspect} />
                <VersionChoice component='xray' title='Версия Xray' disabled={disabled} onPreview={inspect} />
            </div>
            <Group title='Источники геобаз' footer='Выбор сохраняет список управляемых баз. Уже установленные другие базы остаются на месте. Обновление списка само по себе не меняет правила маршрутизации.'>
                <div className='space-y-3 py-4'>
                    {state.sources.map(source => <label key={source.id} className='flex cursor-pointer items-start gap-3'>
                        <input type='checkbox' checked={geo.sources.includes(source.id)} disabled={disabled} onChange={event => changeGeo({ ...geo, sources: event.target.checked ? [...geo.sources, source.id] : geo.sources.filter(id => id !== source.id) })} className='mt-1 size-4 accent-violet-500' />
                        <span><span className='text-[15px]'>{source.kind} · {source.name}</span><span className='block text-[12px] text-muted-foreground'>{source.repository}</span></span>
                    </label>)}
                    <p className='text-[13px] leading-snug text-muted-foreground'>GeoIPSET выводит российские IP из VPN ещё до Xray. Его обход имеет приоритет над доменными правилами внутри Xray.</p>
                </div>
            </Group>
            <Group title='Обновление выбранных геобаз' footer={`Расписание использует время роутера: ${new Date(state.router_time).toLocaleString('ru-RU')}. При ошибке рабочие базы сохраняются.`}>
                <div className='space-y-4 py-4'>
                    <label className='flex items-center gap-3 text-[15px]'><input type='checkbox' checked={geo.auto} disabled={disabled} onChange={e => changeGeo({ ...geo, auto: e.target.checked })} className='size-4 accent-violet-500' />Обновлять автоматически</label>
                    <div className='grid grid-cols-3 gap-3'>
                        <label className='text-[13px] text-muted-foreground'>День<select aria-label='День обновления геобаз' className={field} value={geo.day} disabled={disabled} onChange={e => changeGeo({ ...geo, day: Number(e.target.value) })}>{['Ежедневно', 'Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота'].map((day, i) => <option key={day} value={i - 1}>{day}</option>)}</select></label>
                        <label className='text-[13px] text-muted-foreground'>Час<input aria-label='Час обновления' type='number' min={0} max={23} className={field} value={geo.hour} disabled={disabled} onChange={e => changeGeo({ ...geo, hour: Number(e.target.value) })} /></label>
                        <label className='text-[13px] text-muted-foreground'>Минута<input aria-label='Минута обновления' type='number' min={0} max={59} className={field} value={geo.minute} disabled={disabled} onChange={e => changeGeo({ ...geo, minute: Number(e.target.value) })} /></label>
                    </div>
                    <button className={`${button} w-full`} disabled={disabled || !dirty} onClick={() => saveGeo.mutate()}>Сохранить источники и расписание</button>
                    <button className={`${button} w-full`} disabled={disabled || dirty || geo.sources.length === 0} onClick={() => inspect({ component: 'geodata' })}>Проверить обновление геобаз</button>
                </div>
            </Group>
            <Group title='Параметры XKeen' footer='Доступность определяется по установленной версии XKeen. Каждое изменение сначала показывается для проверки и применяется с резервной копией.'>
                {state.settings.map(setting => {
                    const checked = pendingSetting?.setting.id === setting.id ? pendingSetting.current : setting.enabled
                    const nativeOff = setting.id === 'native_geodata_schedule' && !setting.enabled
                    const hint = nativeOff ? 'Штатная задача XKeen выключена. Здесь её можно только отключить. Для автоматического обновления выберите расписание в разделе геобаз выше.' : setting.supported ? setting.hint : 'Недоступно в установленной версии XKeen.'
                    return <Row key={setting.id} label={setting.name} hint={<>{hint}<span className='mt-1 block'>{checked ? 'Включено' : 'Выключено'}{pendingSetting?.setting.id === setting.id ? ' · ожидаем завершения' : ''}</span></>} trailing={<span className='rounded-full focus-within:outline-2 focus-within:outline-offset-4 focus-within:outline-tint'><Switch checked={checked} label={setting.name} onChange={desired => inspectSetting(setting, desired)} disabled={disabled || !setting.supported || nativeOff} /></span>} />
                })}
                <Row label='Порты и IP-исключения XKeen' to='/settings/xkeen' />
            </Group>
            {preview && <Group title='Проверка перед применением'>
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
            {state.backups.length > 0 && <Group title='Резервные копии компонентов' footer='Откат восстанавливает компонент и сохранённое состояние его установки. Перед применением ещё раз подтвердите действие.'>
                {state.backups.map(backup => <BackupRow key={backup.id} backup={backup} disabled={disabled} onRollback={id => rollback.mutate(id)} />)}
            </Group>}
            <p className='px-4 text-[13px] text-muted-foreground'>Обновления кода панели находятся в разделе <Link className='text-tint' to='/settings/update'>«Обновление панели»</Link>. Подписка обновляется независимо от компонентов.</p>
        </>}
        {settingIntent && <SettingChangeDialog
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
                if (settingReady && settingPreview?.change && !busy) settingApply.mutate({ id: settingPreview.id, setting: settingIntent.setting, current: settingPreview.change.current })
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
    return <div className='space-y-2 py-3'><Row label={`${componentName(backup.component)} · ${backup.version}`} hint={new Date(backup.created).toLocaleString('ru-RU')} detail='Восстановить' onClick={() => setConfirm(v => !v)} disabled={disabled} />{confirm && <><p className='text-[13px] text-muted-foreground'>Восстановить состояние установки из этой копии? VPN кратко перезапустится.</p><button className={`${button} w-full`} disabled={disabled} onClick={() => { onRollback(backup.id); setConfirm(false) }}>Подтвердить восстановление</button></>}</div>
}
