import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { IconLoader2 } from '@tabler/icons-react'
import { api } from '@/lib/api'
import { safeNotice, importWarnings } from '@/lib/subscription'
import type { SubscriptionUpdateResponse } from '@/types'

type SourceKind = 'subscription' | 'server' | 'file'
const labels: Record<SourceKind, string> = { subscription: 'Подписка', server: 'Ссылка сервера', file: 'Файл' }

// The source is never stored in browser storage or filled from saved secrets.
export function ServerSourceForm({ onApplied }: { onApplied: (result: SubscriptionUpdateResponse) => void }) {
    const qc = useQueryClient()
    const [kind, setKind] = useState<SourceKind>('subscription')
    const [value, setValue] = useState('')
    const [fileName, setFileName] = useState('')
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState('')
    const [warnings, setWarnings] = useState<string[]>([])
    const valid = kind === 'subscription' ? /^https?:\/\/\S+$/.test(value.trim()) : value.trim().length > 0
    function changeKind(next: SourceKind) { setKind(next); setValue(''); setFileName(''); setError(''); setWarnings([]) }
    async function submit(event: FormEvent) {
        event.preventDefault()
        if (busy || !valid) return
        setBusy(true); setError(''); setWarnings([])
        try {
            const result = kind === 'subscription'
                ? await api.post<SubscriptionUpdateResponse>('/api/subscription', { url: value.trim() })
                : await api.post<SubscriptionUpdateResponse>('/api/sources/import', { kind, content: value.trim() })
            if (result.pool_error) throw new Error('Серверы не удалось применить. Предыдущее подключение сохранено.')
            setValue(''); setFileName(''); setWarnings(importWarnings(result.import_report, result.warnings))
            await Promise.all(['subscription', 'servers', 'status', 'pool', 'setup', 'routing-mode'].map(key => qc.invalidateQueries({ queryKey: [key] })))
            onApplied(result)
        } catch (e) {
            setError(safeNotice(e instanceof Error ? e.message : undefined, 'Не удалось проверить и применить источник. Прежнее подключение сохранено.'))
        } finally { setBusy(false) }
    }
    return <form onSubmit={submit} className='flex flex-col gap-4 py-4'>
        <div className='grid grid-cols-3 gap-1 rounded-xl bg-fill p-1' aria-label='Источник серверов'>
            {(Object.keys(labels) as SourceKind[]).map(id => <button key={id} type='button' disabled={busy} onClick={() => changeKind(id)} aria-pressed={kind === id}
                className={`min-h-11 cursor-pointer rounded-lg px-2 text-[14px] ${kind === id ? 'bg-white/15 text-foreground' : 'text-muted-foreground'}`}>{labels[id]}</button>)}
        </div>
        <p className='text-[14px] leading-snug text-muted-foreground'>
            {kind === 'subscription' ? 'Ссылка https:// от VPN-провайдера или уже настроенного сервера. Список будет обновляться автоматически.'
                : kind === 'server' ? 'Готовая ссылка vless://, vmess://, trojan://, ss:// или другого поддерживаемого протокола. Одного IP-адреса VPS недостаточно.'
                    : 'Текстовый файл со ссылками серверов или поддерживаемой конфигурацией JSON/YAML. Файл читается в браузере; передаётся только его содержимое, до 4 МиБ.'}
        </p>
        {kind === 'file' ? <>
            <label htmlFor='server-source-file' className='text-[15px] font-medium'>Файл серверов</label>
            <input id='server-source-file' type='file' disabled={busy} accept='.txt,.json,.yaml,.yml,.conf,text/plain,application/json' className='min-h-11 text-[15px]' onChange={async event => {
                setError(''); setValue(''); setFileName('')
                const file = event.target.files?.[0]; if (!file) return
                if (file.size > 4 * 1024 * 1024) { setError('Файл больше 4 МиБ'); return }
                try { setValue(await file.text()); setFileName(file.name) } catch { setError('Не удалось прочитать файл') }
            }} />
            {fileName && <p className='break-all text-[13px] text-muted-foreground'>Выбран: {fileName}</p>}
        </> : <>
            <label htmlFor='server-source-value' className='text-[15px] font-medium'>{kind === 'subscription' ? 'Ссылка на подписку' : 'Ссылка подключения'}</label>
            <input id='server-source-value' type='password' autoComplete='off' autoCapitalize='none' spellCheck={false} disabled={busy} value={value} onChange={event => setValue(event.target.value)}
                placeholder={kind === 'subscription' ? 'https://…' : 'vless://…'} maxLength={kind === 'subscription' ? 8192 : 65536}
                className='min-h-11 w-full rounded-xl border border-white/10 bg-fill px-3 text-[16px] outline-none focus:border-tint' />
        </>}
        {error && <p role='alert' className='text-[14px] text-destructive'>{error}</p>}
        {warnings.length > 0 && <p role='status' className='text-[14px] text-muted-foreground'>{warnings.join(' ')}</p>}
        <button type='submit' disabled={busy || !valid} className='flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl bg-primary px-4 text-[16px] font-semibold text-primary-foreground disabled:opacity-50'>
            {busy && <IconLoader2 className='size-5 animate-spin' />}{busy ? 'Проверяем HTTPS и применяем…' : 'Проверить и подключить'}
        </button>
        <p className='text-[13px] text-muted-foreground'>{kind !== 'subscription' && 'Ручной источник не обновляется по расписанию. '}Ссылки и ключи хранятся только локально на роутере.</p>
    </form>
}
