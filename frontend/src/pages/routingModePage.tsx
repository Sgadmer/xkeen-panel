import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconLoader2 } from '@tabler/icons-react'
import { Group, PageTitle } from '@/components/ios'
import { api } from '@/lib/api'
import { safeNotice } from '@/lib/subscription'

type Mode = 'preserve' | 'selected' | 'all'
type Policy = { mode: Mode; services: string[]; addresses: string[] }
type PolicyResponse = { policy: Policy; services: { id: string; name: string; domains: string[] }[]; core: string; profile_active: boolean }
const choices: { id: Mode; title: string; hint: string }[] = [
    { id: 'selected', title: 'VPN для выбранных сервисов', hint: 'Выбранные сервисы и адреса через VPN, остальное напрямую.' },
    { id: 'all', title: 'VPN для всего, кроме исключений', hint: 'Трафик выбранных устройств через VPN. Ваши исключения и локальная сеть остаются напрямую.' },
    { id: 'preserve', title: 'Сохранить текущую / провайдерскую политику', hint: 'Сохранить прежние правила роутера или маршрутизацию составного профиля подписки.' },
]

export function RoutingModeForm({ onApplied }: { onApplied?: () => void }) {
    const qc = useQueryClient()
    const query = useQuery({ queryKey: ['routing-mode'], queryFn: () => api.get<PolicyResponse>('/api/routing-mode') })
    const [mode, setMode] = useState<Mode>('preserve')
    const [services, setServices] = useState<string[]>([])
    const [addresses, setAddresses] = useState('')
    const [confirmed, setConfirmed] = useState(false)
    const [notice, setNotice] = useState('')
    useEffect(() => {
        if (!query.data) return
        setMode(query.data.policy.mode); setServices(query.data.policy.services); setAddresses(query.data.policy.addresses.join('\n')); setConfirmed(false)
    }, [query.data])
    const save = useMutation({
        mutationFn: (policy: Policy) => api.put<PolicyResponse>('/api/routing-mode', { ...policy, confirm_replace: true }),
        onSuccess: data => {
            qc.setQueryData(['routing-mode'], data)
            qc.invalidateQueries({ queryKey: ['status'] }); qc.invalidateQueries({ queryKey: ['pool'] }); qc.invalidateQueries({ queryKey: ['setup'] })
            setNotice('Режим сохранён и применён.'); setConfirmed(false); onApplied?.()
        },
    })
    function submit(event: FormEvent) {
        event.preventDefault(); if (!confirmed || save.isPending) return
        setNotice('')
        save.mutate({ mode, services, addresses: addresses.split(/\r?\n/).map(s => s.trim()).filter(Boolean) })
    }
    if (query.isPending) return <p className='flex items-center gap-2 px-4 py-4'><IconLoader2 className='size-5 animate-spin' />Читаем действующие правила…</p>
    if (query.error) return <Group><p role='alert' className='py-4 text-destructive'>{query.error.message}</p><button type='button' className='min-h-11 text-tint' onClick={() => query.refetch()}>Повторить</button></Group>
    const unsupported = query.data?.core !== 'xray'
    return <form onSubmit={submit} className='flex flex-col gap-5'>
        {query.data?.profile_active && <Group><p className='py-4 text-[14px] text-muted-foreground'>Этот профиль содержит свои правила. Для ручного режима выберите обычный сервер в разделе «Серверы». До этого доступно сохранение провайдерской политики.</p></Group>}
        {unsupported && <p role='alert' className='px-4 text-destructive'>Выбор режимов доступен при использовании ядра Xray.</p>}
        <Group title='Как направлять трафик'>
            {choices.map(choice => <label key={choice.id} className='flex cursor-pointer items-start gap-3 py-4'>
                <input type='radio' name='routing-mode' value={choice.id} checked={mode === choice.id} onChange={() => { setMode(choice.id); setConfirmed(false); setNotice('') }}
                    disabled={save.isPending || unsupported || !!query.data?.profile_active && choice.id !== 'preserve'} className='mt-1 size-5 shrink-0 accent-indigo-500' />
                <span><span className='text-[16px] font-medium'>{choice.title}</span><span className='mt-1 block text-[13px] text-muted-foreground'>{choice.hint}</span></span>
            </label>)}
        </Group>
        {mode === 'selected' && <>
            <Group title='Сервисы' footer='Подборки содержат известные домены. Для дополнительных адресов используйте поле ниже. Списки могут требовать дополнения по логам приложения.'>
                {query.data?.services.map(service => <label key={service.id} className='flex min-h-12 cursor-pointer items-center gap-3 py-3'>
                    <input type='checkbox' checked={services.includes(service.id)} disabled={save.isPending} onChange={event => setServices(old => event.target.checked ? [...old, service.id] : old.filter(id => id !== service.id))} className='size-5 accent-indigo-500' />
                    <span className='text-[16px]'>{service.name}</span>
                </label>)}
            </Group>
            <Group title='Дополнительные адреса через VPN' footer='Один домен, URL, IP или CIDR на строку. Домен включает поддомены; full: задаёт точное имя. Пустой список означает прямое подключение для всего трафика.'>
                <label htmlFor='routing-addresses' className='sr-only'>Дополнительные адреса через VPN</label>
                <textarea id='routing-addresses' value={addresses} onChange={event => setAddresses(event.target.value)} disabled={save.isPending} rows={5} placeholder={'example.com\n203.0.113.0/24'} spellCheck={false} autoCapitalize='none'
                    className='my-3 min-h-32 w-full resize-y rounded-xl bg-fill px-3 py-2 text-[15px] outline-none focus:ring-1 focus:ring-tint' />
            </Group>
        </>}
        <Group title='Применение' footer='Режим управляет трафиком, поступающим в Xray. Политики устройств, IP/GeoIPSET и исключения портов в XKeen действуют до него; при миграции их нужно согласовать отдельно. Исходные правила сохраняются и возвращаются в режиме сохранения политики.'>
            <label className='flex cursor-pointer items-start gap-3 py-4 text-[14px]'>
                <input type='checkbox' checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={save.isPending || unsupported} className='mt-0.5 size-5 shrink-0 accent-indigo-500' />
                <span>Применить выбранный режим. VPN кратко перезапустится; исключения сохранятся.</span>
            </label>
            <button type='submit' disabled={!confirmed || save.isPending || unsupported} className='mb-4 flex min-h-12 w-full cursor-pointer items-center justify-center gap-2 rounded-xl bg-primary px-4 text-[16px] font-semibold text-primary-foreground disabled:opacity-50'>
                {save.isPending && <IconLoader2 className='size-5 animate-spin' />}{save.isPending ? 'Применяем…' : 'Сохранить режим'}
            </button>
        </Group>
        {save.error && <p role='alert' className='px-4 text-[14px] text-destructive'>{safeNotice(save.error.message, 'Режим не удалось применить. Прежние настройки сохранены.')}</p>}
        <p role='status' className='px-4 text-[14px] text-tint empty:hidden'>{notice}</p>
    </form>
}

export function RoutingModePage() {
    return <><PageTitle title='Маршрутизация VPN' subtitle='Выберите, какие подключения должны идти через VPN.' back={{ to: '/settings', label: 'Настройки' }} /><RoutingModeForm /></>
}
