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
import type { MultiPool, PoolMember, Server, ServerSource, SubscriptionUpdateResponse } from '@/types'

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
                hint={[kinds[item.kind], item.host !== item.name && item.host, 'Записей: ' + item.server_count, item.imported_profiles && `Режимов провайдера: ${item.imported_profiles}`,
                    item.skipped_composite && `Пропущено составных профилей: ${item.skipped_composite}`,
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
    // The link is never stored in browser storage or filled from saved secrets.
    const [link, setLink] = useState('')
    const validLink = /^https?:\/\/\S+$/.test(link.trim())
    const path = '/api/sources/' + encodeURIComponent(source.id)
    const action = useMutation({
        mutationFn: async (kind: 'rename' | 'refresh' | 'delete' | 'replace') => {
            if (kind === 'delete') return api.del<SubscriptionUpdateResponse>(path)
            if (kind === 'rename') return api.put<SubscriptionUpdateResponse>(path, { name: name.trim() })
            if (kind === 'replace') return api.post<SubscriptionUpdateResponse>(path + '/url', { url: link.trim() })
            return api.post<SubscriptionUpdateResponse>(path + '/refresh')
        },
        onSuccess: async (result, kind) => {
            await invalidateServerData(qc)
            const message = { rename: 'Название сохранено.', refresh: 'Подписка обновлена.', delete: 'Источник удалён.',
                replace: 'Ссылка заменена. Серверы с прежними названиями остались выбранными.' }[kind]
            onDone([message, ...importWarnings(result.import_report, result.warnings),
                ...(result.pool_error ? [safeNotice(result.pool_error, 'Не удалось обновить пул.')] : [])].join(' '))
        },
    })
    const ago = timeAgo(source.last_updated)
    return <>
        <Back onClick={onBack} />
        <Group title='Источник'>
            <Row label={kinds[source.kind]} hint={source.host} detail={'Записей: ' + source.server_count} />
            {!!source.imported_profiles && <Row label='Доступные режимы провайдера' detail={String(source.imported_profiles)} />}
            {!!source.skipped_composite && <Row label='Пропущено составных профилей' detail={String(source.skipped_composite)}
                hint='Эти профили используют функции, которые панель не может перенести.' />}
            {!!source.skipped_unsupported && <Row label='Прочие неподдерживаемые записи' detail={String(source.skipped_unsupported)} />}
            <form className='space-y-2 py-3' onSubmit={event => { event.preventDefault(); if (name.trim() && !action.isPending) action.mutate('rename') }}>
                <label className='flex flex-col gap-1 text-sm'>Название источника
                    <input className={field} required maxLength={80} value={name} disabled={action.isPending} onChange={event => setName(event.target.value)} />
                </label>
                <button disabled={action.isPending || !name.trim() || name.trim() === source.name} className='min-h-10 font-semibold text-tint disabled:opacity-40'>Сохранить название</button>
            </form>
            {source.can_refresh && <Row label={action.isPending && action.variables === 'refresh' ? 'Обновляем…' : 'Обновить подписку'}
                hint={ago ? 'Последнее обновление · ' + ago : undefined} tone='tint' disabled={action.isPending} onClick={() => action.mutate('refresh')} />}
        </Group>
        {source.can_refresh && <Group title='Провайдер выдал новую ссылку'>
            {source.native_provider
                ? <p className='py-3 text-sm text-muted-foreground'>Этот источник привязан к профилю Mihomo, поэтому ссылку в нём заменить нельзя. Добавьте новую ссылку отдельным источником и удалите этот. Серверы с теми же параметрами останутся выбранными.</p>
                : <form className='space-y-2 py-3' onSubmit={event => { event.preventDefault(); if (validLink && !action.isPending) action.mutate('replace') }}>
                    <label className='flex flex-col gap-1 text-sm'>Новая ссылка подписки
                        <input className={field} type='password' autoComplete='off' autoCapitalize='none' spellCheck={false} maxLength={8192} placeholder='https://…'
                            value={link} disabled={action.isPending} onChange={event => setLink(event.target.value)} />
                    </label>
                    <p className='text-[13px] text-muted-foreground'>Нужна, если подписка перестала обновляться, потому что провайдер сменил её адрес. Серверы с прежними названиями останутся выбранными в сервисах и пулах.</p>
                    <button disabled={action.isPending || !validLink} className='min-h-10 font-semibold text-tint disabled:opacity-40'>
                        {action.isPending && action.variables === 'replace' ? 'Заменяем ссылку…' : 'Заменить ссылку'}
                    </button>
                </form>}
        </Group>}
        <Group footer={confirmDelete ? (source.native_provider
            ? 'Серверы исчезнут из каталога. Пулы заполнятся серверами других подписок. Связанный провайдер Mihomo отключится. Группы профиля, где был выбран сервер этой подписки, начнут блокировать трафик, пока вы не выберете другой.'
            : 'Серверы исчезнут из каталога. Пулы заполнятся серверами других подписок. Сервис с отдельным сервером, которого больше нет ни в одной подписке, будет заблокирован, пока вы не выберете другой.') : undefined}>
            <Row label={confirmDelete ? 'Подтвердить удаление «' + source.name + '»' : 'Удалить источник'} tone='destructive' disabled={action.isPending}
                onClick={() => confirmDelete ? action.mutate('delete') : setConfirmDelete(true)} />
            {confirmDelete && <Row label='Оставить источник' disabled={action.isPending} onClick={() => setConfirmDelete(false)} />}
        </Group>
        <ErrorNotice error={action.error} />
    </>
}

export function MultiPoolsSheet({ open, onClose, initialId }: { open: boolean; onClose: () => void; initialId: string | null }) {
    return <Sheet open={open} onClose={onClose} title='Мультипулы'>
        {open && <MultiPoolList initialId={initialId} />}
    </Sheet>
}

function MultiPoolList({ initialId }: { initialId: string | null }) {
    const pools = useMultiPools()
    const sources = useServerSources()
    const routing = usePool()
    const [edit, setEdit] = useState<string | null>(initialId)
    const [notice, setNotice] = useState('')
    const current = pools.data?.pools?.find(item => item.id === edit)
    const active = routing.data?.selection_kind === 'auto' ? routing.data.auto_scope_id : routing.data?.pinned_tag
    if (edit === 'add' || current) return <MultiPoolEditor key={edit} pool={current} sources={sources.data || []} active={!!current && current.id === active}
        onBack={() => setEdit(null)} onDone={message => { setNotice(message); setEdit(null) }} />
    return <>
        {notice && <p role='status' className='text-sm text-muted-foreground'>{notice}</p>}
        <ErrorNotice error={pools.error || sources.error} />
        <Group footer='Мультипул выбирает доступный VPN-сервер с наименьшей задержкой. Назначить пул отдельному сервису можно в разделе «Сервисы».'>
            {pools.isLoading && <Row label='Загружаем пулы…' />}
            {pools.data?.pools?.map(item => {
                const selected = item.source_ids?.map(id => sources.data?.find(source => source.id === id)?.name || 'Удалённый источник')
                const countryText = item.countries?.length ? item.countries.map(countryLabel).join(', ') : 'Все разрешённые страны'
                return <Row key={item.id} label={<span className='break-words'>{item.name}</span>}
                    hint={[active === item.id && 'Основной маршрут', item.include_filtered !== false && (selected?.length ? selected.join(', ') : 'Все источники'), item.include_filtered !== false && countryText,
                        !!item.members?.length && `Конфигов вручную: ${item.members.length}`,
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
    const scopes = useMultiPools().data?.scopes
    const settings = usePanelSettings()
    const excluded = settings.data?.avoid_countries ?? []
    const [name, setName] = useState(pool?.name || '')
    const [mode, setMode] = useState<'rules' | 'manual' | 'mixed'>(!pool || pool.include_filtered === false ? 'manual' : pool.members?.length ? 'mixed' : 'rules')
    const [members, setMembers] = useState<PoolMember[]>(pool?.members || [])
    const [search, setSearch] = useState('')
    const [selectedOnly, setSelectedOnly] = useState(false)
    const filterEnabled = mode !== 'manual'
    const explicitEnabled = mode !== 'rules'
    const [sourceIds, setSourceIds] = useState<string[]>(pool?.source_ids || [])
    const [allSources, setAllSources] = useState(!pool?.source_ids?.length)
    const [countries, setCountries] = useState<string[]>(pool?.countries || [])
    const [allCountries, setAllCountries] = useState(!pool?.countries?.length)
    const [confirmDelete, setConfirmDelete] = useState(false)
    const sourceOptions = [...sources.map(source => ({ id: source.id, name: source.name })),
        ...sourceIds.filter(id => !sources.some(item => item.id === id)).map(id => ({ id, name: 'Удалённый источник' }))]
    const sourceServers = (servers.data ?? []).filter(s => s.protocol !== 'xray-profile' && (allSources || sourceIds.includes(s.source_id || 'legacy')))
    const availableCountries = [...new Set([...sourceServers.map(serverCountry), ...countries])].filter(Boolean)
        .sort((a, b) => countryLabel(a).localeCompare(countryLabel(b), 'ru'))
    const selectedKeys = new Set(members.map(memberKey))
    const choices = new Map<string, Server>()
    for (const server of servers.data ?? []) {
        if (!server.target_id || server.protocol === 'xray-profile') continue
        const key = memberKey({ source_id: server.source_id || 'legacy', target_id: server.target_id })
        if (!choices.has(key)) choices.set(key, server)
    }
    const normalized = search.trim().toLocaleLowerCase('ru')
    const matches = [...choices.entries()].filter(([key, server]) =>
        (!selectedOnly || selectedKeys.has(key)) &&
        [server.name, server.source_name, countryLabel(serverCountry(server))].join(' ').toLocaleLowerCase('ru').includes(normalized))
    const missing = members.filter(member => !choices.has(memberKey(member)))
    const rulesValid = !filterEnabled || (allSources || !!sourceIds.length) && (allCountries || !!countries.length)
    const valid = !!name.trim() && rulesValid && (mode !== 'manual' || members.length > 0)
    const finalSourceIds = filterEnabled && !allSources ? sourceIds : []
    const finalCountries = filterEnabled && !allCountries ? countries : []
    const finalMembers = explicitEnabled ? members : []
    const dirty = !pool || name.trim() !== pool.name ||
        filterEnabled !== (pool.include_filtered !== false) ||
        !sameSet(finalSourceIds, pool.source_ids || []) ||
        !sameSet(finalCountries, pool.countries || []) ||
        !sameSet(finalMembers.map(memberKey), (pool.members || []).map(memberKey))
    const path = '/api/multipools' + (pool ? '/' + encodeURIComponent(pool.id) : '')
    const action = useMutation({
        mutationFn: async (kind: 'save' | 'delete' | 'pin' | 'auto') => {
            if (kind === 'delete') return api.del(path)
            if (kind === 'pin') return api.post('/api/pool/scope', { id: pool!.id })
            if (kind === 'auto') {
                const all = scopes?.find(scope => scope.kind === 'all')
                if (!all) throw new Error('Не удалось загрузить общий пул')
                return api.post('/api/pool/scope', { id: all.id })
            }
            const data = { name: name.trim(), source_ids: finalSourceIds, countries: finalCountries,
                include_filtered: filterEnabled, members: finalMembers }
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
        <Group title='Состав пула'>
            <label className='flex min-h-12 flex-wrap items-center justify-between gap-2 py-2 text-sm'>
                Способ добавления
                <select className='min-h-10 max-w-full rounded-xl border border-white/10 bg-fill px-2' disabled={action.isPending}
                    value={mode} onChange={e => setMode(e.target.value as typeof mode)}>
                    <option value='rules'>По странам и подпискам</option>
                    <option value='manual'>Отдельные конфиги</option>
                    <option value='mixed'>По условиям и вручную</option>
                </select>
            </label>
            {filterEnabled && <>
                <details className='py-2'>
                    <summary className='cursor-pointer py-1 text-[15px]'>Подписки · {allSources ? 'все' : sourceIds.length === 1 ? (sourceOptions.find(s => s.id === sourceIds[0])?.name || '1') : sourceIds.length}</summary>
                    <Choice checked={allSources} disabled={action.isPending} label='Все, включая новые подписки' onChange={() => setAllSources(!allSources)} />
                    {!allSources && sourceOptions.map(source => <Choice key={source.id} label={source.name} checked={sourceIds.includes(source.id)}
                        disabled={action.isPending} onChange={() => setSourceIds(ids => toggle(ids, source.id))} />)}
                </details>
                <details className='py-2'>
                    <summary className='cursor-pointer py-1 text-[15px]'>Страны · {allCountries ? 'все разрешённые' : countries.length === 1 ? countryLabel(countries[0]) : countries.length}</summary>
                    <Choice checked={allCountries} disabled={action.isPending} label='Все разрешённые страны' onChange={() => setAllCountries(!allCountries)} />
                    {!allCountries && <div className='grid grid-cols-2 gap-x-3'>{availableCountries.map(code =>
                        <Choice key={code} label={countryLabel(code) + (excluded.includes(code) ? ' · исключена' : '')}
                            checked={countries.includes(code)} disabled={action.isPending || excluded.includes(code) && !countries.includes(code)}
                            onChange={() => setCountries(list => toggle(list, code))} />)}</div>}
                    {!allCountries && !availableCountries.length && <Row label={servers.isLoading ? 'Загружаем страны…' : 'В выбранных подписках пока нет серверов с известной страной.'} />}
                </details>
            </>}
        </Group>
        {explicitEnabled && <Group title={`Конфиги · выбрано ${members.length}`} footer={mode === 'mixed' ? 'Выбранные конфиги дополняют серверы, найденные по условиям. Исключённые страны пропускаются.' : 'Пул использует отмеченные конфиги из любых подписок. Исключённые страны пропускаются.'}>
            <div className='space-y-1 py-2'>
                <input type='search' aria-label='Найти конфиг' placeholder='Название, страна или подписка' className={field}
                    value={search} onChange={e => setSearch(e.target.value)} />
                <Choice checked={selectedOnly} disabled={false} label='Показать только выбранные' onChange={() => setSelectedOnly(!selectedOnly)} />
            </div>
            <div className='max-h-72 overflow-auto overscroll-contain divide-y divide-white/10'>
                {matches.map(([key, server]) => {
                    const code = serverCountry(server)
                    const selected = selectedKeys.has(key)
                    return <Choice key={key} checked={selected} disabled={action.isPending || excluded.includes(code) && !selected}
                        label={server.name} hint={[server.source_name, countryLabel(code), server.protocol, excluded.includes(code) && 'Исключённая страна'].filter(Boolean).join(' · ')}
                        onChange={() => setMembers(prev => selected ? prev.filter(item => memberKey(item) !== key) :
                            [...prev, { source_id: server.source_id || 'legacy', target_id: server.target_id! }])} />
                })}
                {!servers.isLoading && missing.map(member => <Choice key={memberKey(member)} checked disabled={action.isPending}
                    label='Конфиг отсутствует в подписке' hint={sources.find(item => item.id === member.source_id)?.name}
                    onChange={() => setMembers(prev => prev.filter(item => memberKey(item) !== memberKey(member)))} />)}
                {servers.isLoading && <Row label='Загружаем конфиги…' />}
                {!servers.isLoading && !matches.length && !missing.length && <Row label={selectedOnly && !members.length ? 'Конфиги ещё не выбраны' : 'Подходящих конфигов нет'} />}
            </div>
        </Group>}
        <ErrorNotice error={action.error || servers.error || settings.error} />
        <Group>
            <Row label={action.isPending && action.variables === 'save' ? 'Сохраняем…' : 'Сохранить мультипул'} tone='tint'
                disabled={!valid || !dirty || action.isPending || !servers.data || !settings.data} onClick={() => action.mutate('save')} />
        </Group>
        {pool && <Group title='Основной маршрут'>
            <Row label={active ? 'Вернуть общий автовыбор' : 'Назначить основным маршрутом'}
                hint={pool.member_count ? (active ? 'Этот пул уже выбран для основного маршрута.' : 'Для сервисов со своим маршрутом сохраняется их выбор.')
                    : 'Подходящих VPN-серверов нет. Трафик, назначенный этому пулу, блокируется.'}
                tone='tint' disabled={dirty || action.isPending || (!active && !pool.member_count)} onClick={() => action.mutate(active ? 'auto' : 'pin')} />
        </Group>}
        {pool && <Group>
            <Row label={confirmDelete ? 'Подтвердить удаление «' + pool.name + '»' : 'Удалить мультипул'} tone='destructive'
                disabled={action.isPending} onClick={() => confirmDelete ? action.mutate('delete') : setConfirmDelete(true)} />
            {confirmDelete && <Row label='Оставить мультипул' disabled={action.isPending} onClick={() => setConfirmDelete(false)} />}
        </Group>}
    </>
}

function memberKey(member: PoolMember) {
    return member.source_id + ':' + member.target_id
}

function Choice({ checked, disabled, label, hint, onChange }: { checked: boolean; disabled: boolean; label: string; hint?: string; onChange: () => void }) {
    return <label className='flex min-h-11 cursor-pointer items-center gap-3 py-2 has-disabled:opacity-50'>
        <input type='checkbox' className='size-5 shrink-0 accent-[var(--primary)]' checked={checked} disabled={disabled} onChange={onChange} />
        <span className='min-w-0 break-words'>{label}{hint && <span className='block text-xs text-muted-foreground'>{hint}</span>}</span>
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
