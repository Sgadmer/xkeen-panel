import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { IconChevronLeft, IconChevronRight } from '@tabler/icons-react'
import { Group, Row } from '@/components/ios'
import { ServerSourceForm } from '@/components/serverSourceForm'
import { Sheet } from '@/components/sheet'
import { useMultiPools, usePanelSettings, usePool, useServers, useServerSources } from '@/hooks/usePanelData'
import { invalidateServerData } from '@/hooks/useServerActions'
import { api } from '@/lib/api'
import { countryLabel, serverCountry, timeAgo } from '@/lib/format'
import { importWarnings, safeNotice } from '@/lib/subscription'
import type { MultiPool, ServerSource, SubscriptionUpdateResponse } from '@/types'

const field = 'min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 text-[16px] outline-none focus:border-tint'
const arrow = <IconChevronRight className='size-4 shrink-0 text-label-tertiary' />
const kinds = { subscription: 'Подписка', server: 'Ссылка сервера', file: 'Файл' }

function Back({ onClick }: { onClick: () => void }) {
    return <button type='button' className='flex min-h-10 items-center gap-1 self-start text-tint' onClick={onClick}>
        <IconChevronLeft className='size-4' />К списку
    </button>
}

function ErrorNotice({ error }: { error: Error | null }) {
    return error && <p role='alert' className='text-sm text-destructive'>{safeNotice(error.message, 'Не удалось выполнить запрос.')}</p>
}

export function SourcesSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
    return <Sheet open={open} onClose={onClose} title='Подписки и источники'>
        {open && <SourceList />}
    </Sheet>
}

function SourceList() {
    const sources = useServerSources()
    const [edit, setEdit] = useState<string | null>(null)
    const [notice, setNotice] = useState('')
    const current = sources.data?.find(item => item.id === edit)
    function select(id: string | null) { setNotice(''); setEdit(id) }
    function finish(message: string) { setEdit(null); setNotice(message) }
    if (edit === 'add') return <>
        <Back onClick={() => select(null)} />
        <Group title='Новый источник'>
            <ServerSourceForm onApplied={result => finish(['Источник добавлен.', ...importWarnings(result.import_report, result.warnings)].join(' '))} />
        </Group>
    </>
    if (current) return <SourceEditor key={current.id} source={current} onBack={() => select(null)} onDone={finish} />
    return <>
        {notice && <p role='status' className='text-sm text-muted-foreground'>{notice}</p>}
        <ErrorNotice error={sources.error} />
        <Group>
            {sources.isLoading && <Row label='Загружаем источники…' />}
            {sources.data?.map(item => <Row key={item.id} label={<span className='break-words'>{item.name}</span>}
                hint={[kinds[item.kind], item.host !== item.name && item.host, 'Серверов: ' + item.server_count,
                    item.native_provider && 'Используется профилем Mihomo'].filter(Boolean).join(' · ')}
                onClick={() => select(item.id)} trailing={arrow} />)}
            <Row label='Добавить источник' tone='tint' onClick={() => select('add')} />
        </Group>
    </>
}

function SourceEditor({ source, onBack, onDone }: { source: ServerSource; onBack: () => void; onDone: (notice: string) => void }) {
    const qc = useQueryClient()
    const [name, setName] = useState(source.name)
    const [confirmDelete, setConfirmDelete] = useState(false)
    const path = '/api/sources/' + encodeURIComponent(source.id)
    const action = useMutation({
        mutationFn: async (kind: 'rename' | 'refresh' | 'delete') => {
            if (kind === 'delete') return api.del<SubscriptionUpdateResponse>(path)
            if (kind === 'rename') return api.put<SubscriptionUpdateResponse>(path, { name: name.trim() })
            return api.post<SubscriptionUpdateResponse>(path + '/refresh')
        },
        onSuccess: async (result, kind) => {
            await invalidateServerData(qc)
            const message = { rename: 'Название сохранено.', refresh: 'Подписка обновлена.', delete: 'Источник удалён.' }[kind]
            onDone([message, ...importWarnings(result.import_report, result.warnings),
                ...(result.pool_error ? [safeNotice(result.pool_error, 'Не удалось обновить пул.')] : [])].join(' '))
        },
    })
    const ago = timeAgo(source.last_updated)
    return <>
        <Back onClick={onBack} />
        <Group title='Источник'>
            <Row label={kinds[source.kind]} hint={source.host} detail={'Серверов: ' + source.server_count} />
            <form className='space-y-2 py-3' onSubmit={event => { event.preventDefault(); if (name.trim() && !action.isPending) action.mutate('rename') }}>
                <label className='flex flex-col gap-1 text-sm'>Название источника
                    <input className={field} required maxLength={80} value={name} disabled={action.isPending} onChange={event => setName(event.target.value)} />
                </label>
                <button disabled={action.isPending || !name.trim() || name.trim() === source.name} className='min-h-10 font-semibold text-tint disabled:opacity-40'>Сохранить название</button>
            </form>
            {source.can_refresh && <Row label={action.isPending && action.variables === 'refresh' ? 'Обновляем…' : 'Обновить подписку'}
                hint={ago ? 'Последнее обновление · ' + ago : undefined} tone='tint' disabled={action.isPending} onClick={() => action.mutate('refresh')} />}
        </Group>
        <Group footer={confirmDelete ? (source.native_provider
            ? 'Серверы исчезнут из каталога и мультипулов. Связанные провайдеры Mihomo отключатся. Пустые группы будут блокировать трафик. Если в группе закреплён удаляемый узел, сначала смените выбор.'
            : 'Серверы этого источника исчезнут из каталога и мультипулов. Перед удалением можно назначить сервисам другой сервер.') : undefined}>
            <Row label={confirmDelete ? 'Подтвердить удаление «' + source.name + '»' : 'Удалить источник'} tone='destructive' disabled={action.isPending}
                onClick={() => confirmDelete ? action.mutate('delete') : setConfirmDelete(true)} />
            {confirmDelete && <Row label='Оставить источник' disabled={action.isPending} onClick={() => setConfirmDelete(false)} />}
        </Group>
        <ErrorNotice error={action.error} />
    </>
}

export function MultiPoolsSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
    return <Sheet open={open} onClose={onClose} title='Мультипулы'>
        {open && <MultiPoolList />}
    </Sheet>
}

function MultiPoolList() {
    const pools = useMultiPools()
    const sources = useServerSources()
    const routing = usePool()
    const [edit, setEdit] = useState<string | null>(null)
    const [notice, setNotice] = useState('')
    const current = pools.data?.find(item => item.id === edit)
    const active = routing.data?.pinned_tag
    if (edit === 'add' || current) return <MultiPoolEditor key={edit} pool={current} sources={sources.data || []} active={!!current && current.id === active}
        onBack={() => setEdit(null)} onDone={message => { setNotice(message); setEdit(null) }} />
    return <>
        {notice && <p role='status' className='text-sm text-muted-foreground'>{notice}</p>}
        <ErrorNotice error={pools.error || sources.error} />
        <Group footer='Мультипул выбирает доступный VPN-сервер с наименьшей задержкой. Назначить пул отдельному сервису можно в разделе «Сервисы».'>
            {pools.isLoading && <Row label='Загружаем пулы…' />}
            {pools.data?.map(item => {
                const selected = item.source_ids?.map(id => sources.data?.find(source => source.id === id)?.name || 'Удалённый источник')
                const countryText = item.countries?.length ? item.countries.map(countryLabel).join(', ') : 'Все разрешённые страны'
                return <Row key={item.id} label={<span className='break-words'>{item.name}</span>}
                    hint={[active === item.id && 'Основной маршрут', selected?.length ? selected.join(', ') : 'Все источники', countryText,
                        memberSummary(item)].filter(Boolean).join(' · ')}
                    onClick={() => { setNotice(''); setEdit(item.id) }} trailing={arrow} />
            })}
            <Row label='Создать мультипул' tone='tint' disabled={!sources.data || !pools.data} onClick={() => { setNotice(''); setEdit('add') }} />
        </Group>
    </>
}

function MultiPoolEditor({ pool, sources, active, onBack, onDone }: {
    pool?: MultiPool; sources: ServerSource[]; active: boolean; onBack: () => void; onDone: (notice: string) => void
}) {
    const qc = useQueryClient()
    const servers = useServers()
    const settings = usePanelSettings()
    const excluded = settings.data?.avoid_countries ?? []
    const [name, setName] = useState(pool?.name || '')
    const [sourceIds, setSourceIds] = useState<string[]>(pool?.source_ids || [])
    const [allSources, setAllSources] = useState(!pool?.source_ids?.length)
    const [countries, setCountries] = useState<string[]>(pool?.countries || [])
    const [allCountries, setAllCountries] = useState(!pool?.countries?.length)
    const [confirmDelete, setConfirmDelete] = useState(false)
    const sourceOptions = [...sources.map(source => ({ id: source.id, name: source.name })),
        ...sourceIds.filter(id => !sources.some(item => item.id === id)).map(id => ({ id, name: 'Удалённый источник' }))]
    const sourceServers = (servers.data ?? []).filter(s => s.protocol !== 'xray-profile' && (allSources || sourceIds.includes(s.source_id ?? '')))
    const availableCountries = [...new Set([...sourceServers.map(serverCountry), ...countries])].filter(Boolean)
        .sort((a, b) => countryLabel(a).localeCompare(countryLabel(b), 'ru'))
    const valid = !!name.trim() && (allSources || !!sourceIds.length) && (allCountries || !!countries.length)
    const dirty = !pool || name.trim() !== pool.name ||
        !sameSet(allSources ? [] : sourceIds, pool.source_ids || []) ||
        !sameSet(allCountries ? [] : countries, pool.countries || [])
    const path = '/api/multipools' + (pool ? '/' + encodeURIComponent(pool.id) : '')
    const action = useMutation({
        mutationFn: async (kind: 'save' | 'delete' | 'pin' | 'auto') => {
            if (kind === 'delete') return api.del(path)
            if (kind === 'pin') return api.post('/api/pool/pin', { tag: pool!.id })
            if (kind === 'auto') return api.post('/api/pool/auto')
            const data = { name: name.trim(), source_ids: allSources ? [] : sourceIds, countries: allCountries ? [] : countries }
            return pool ? api.put(path, data) : api.post(path, data)
        },
        onSuccess: async (_, kind) => {
            await invalidateServerData(qc)
            onDone({ save: 'Мультипул сохранён.', delete: 'Мультипул удалён.', pin: 'Мультипул назначен основным маршрутом.', auto: 'Включён общий автовыбор.' }[kind])
        },
    })
    return <>
        <Back onClick={onBack} />
        <Group title={pool ? 'Параметры пула' : 'Новый пул'}>
            <label className='flex flex-col gap-1 py-3 text-sm'>Название мультипула
                <input className={field} maxLength={64} value={name} disabled={action.isPending} onChange={e => setName(e.target.value)} placeholder='Например, Европа' />
            </label>
        </Group>
        <Group title='Источники' footer={allSources ? 'Новые подписки тоже будут входить в этот пул.' : undefined}>
            <Choice checked={allSources} disabled={action.isPending} label='Все источники' onChange={() => setAllSources(!allSources)} />
            {!allSources && sourceOptions.map(source => <Choice key={source.id} label={source.name} checked={sourceIds.includes(source.id)}
                disabled={action.isPending} onChange={() => setSourceIds(ids => toggle(ids, source.id))} />)}
            {!allSources && !sourceOptions.length && <Row label='Сначала добавьте источник в разделе «Подписки и источники».' />}
        </Group>
        <Group title='Страны' footer='Страны, исключённые в настройках панели, пропускаются во всех мультипулах.'>
            <Choice checked={allCountries} disabled={action.isPending} label='Все разрешённые страны' onChange={() => setAllCountries(!allCountries)} />
            {!allCountries && availableCountries.map(code => <Choice key={code} label={countryLabel(code) + (excluded.includes(code) ? ' · исключена в настройках' : '')}
                checked={countries.includes(code)} disabled={action.isPending || excluded.includes(code) && !countries.includes(code)}
                onChange={() => setCountries(list => toggle(list, code))} />)}
            {!allCountries && !availableCountries.length && <Row label={servers.isLoading ? 'Загружаем страны…' : 'В выбранных источниках пока нет серверов с известной страной.'} />}
        </Group>
        <ErrorNotice error={action.error || servers.error || settings.error} />
        <Group>
            <Row label={action.isPending && action.variables === 'save' ? 'Сохраняем…' : 'Сохранить мультипул'} tone='tint'
                disabled={!valid || !dirty || action.isPending} onClick={() => action.mutate('save')} />
        </Group>
        {pool && <Group title='Основной маршрут'>
            <Row label={active ? 'Вернуть общий автовыбор' : 'Назначить основным маршрутом'}
                hint={pool.member_count ? (active ? 'Этот пул уже выбран для основного маршрута.' : 'Для сервисов со своим маршрутом сохраняется их выбор.')
                    : 'Подходящих VPN-серверов нет. Трафик, назначенный этому пулу, блокируется.'}
                tone='tint' disabled={dirty || action.isPending} onClick={() => action.mutate(active ? 'auto' : 'pin')} />
        </Group>}
        {pool && <Group>
            <Row label={confirmDelete ? 'Подтвердить удаление «' + pool.name + '»' : 'Удалить мультипул'} tone='destructive'
                disabled={action.isPending} onClick={() => confirmDelete ? action.mutate('delete') : setConfirmDelete(true)} />
            {confirmDelete && <Row label='Оставить мультипул' disabled={action.isPending} onClick={() => setConfirmDelete(false)} />}
        </Group>}
    </>
}

function Choice({ checked, disabled, label, onChange }: { checked: boolean; disabled: boolean; label: string; onChange: () => void }) {
    return <label className='flex min-h-11 cursor-pointer items-center gap-3 py-2 has-disabled:opacity-50'>
        <input type='checkbox' className='size-5 shrink-0 accent-[var(--primary)]' checked={checked} disabled={disabled} onChange={onChange} />
        <span className='min-w-0 break-words'>{label}</span>
    </label>
}

function toggle(values: string[], value: string) {
    return values.includes(value) ? values.filter(item => item !== value) : [...values, value]
}

function sameSet(a: string[], b: string[]) {
    return a.length === b.length && a.every(item => b.includes(item))
}

function memberSummary(pool: MultiPool) {
    if (!pool.member_count) return 'Нет подходящих серверов'
    if (pool.eligible_count && pool.eligible_count > pool.member_count)
        return `В пуле ${pool.member_count} из ${pool.eligible_count} подходящих серверов`
    return 'Серверов: ' + pool.member_count
}
