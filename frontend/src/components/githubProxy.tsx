import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Group } from '@/components/ios'
import { api } from '@/lib/api'
import type { SettingsResponse } from '@/types'

// The proxy XKeen itself downloads its updates through.
export function GithubProxy() {
    const qc = useQueryClient()
    const settings = useQuery({
        queryKey: ['xkeen-settings'],
        queryFn: () => api.get<SettingsResponse>('/api/xkeen/settings'),
    })
    const [ghProxy, setGhProxy] = useState('')

    useEffect(() => {
        const proxy = settings.data?.settings?.xkeen?.gh_proxy
        setGhProxy(typeof proxy === 'string' ? proxy : '')
    }, [settings.data])

    const save = useMutation({
        mutationFn: () => {
            const current = settings.data?.settings ?? {}
            const section = {
                ...((current.xkeen as Record<string, unknown>) ?? {}),
            }
            if (ghProxy.trim()) section.gh_proxy = ghProxy.trim()
            else delete section.gh_proxy
            const next = { ...current }
            if (Object.keys(section).length > 0) next.xkeen = section
            else delete next.xkeen
            return api.put('/api/xkeen/settings', { settings: next })
        },
        onSuccess: () => qc.invalidateQueries({ queryKey: ['xkeen-settings'] }),
    })

    return (
        <Group
            title='Загрузки с GitHub'
            footer={
                save.error ? (
                    <span role='alert' className='text-destructive'>{save.error.message}</span>
                ) : save.isSuccess ? (
                    <span className='text-success'>Сохранено</span>
                ) : (
                    'Прокси, через который XKeen скачивает обновления, когда GitHub недоступен напрямую. Если загрузки идут и так, оставьте поле пустым.'
                )
            }
        >
            <div className='flex flex-col gap-2 py-3'>
                <label htmlFor='gh-proxy' className='sr-only'>
                    Прокси для GitHub
                </label>
                <input
                    id='gh-proxy'
                    value={ghProxy}
                    onChange={e => setGhProxy(e.target.value)}
                    placeholder='https://gh-proxy.com'
                    className='min-h-11 w-full rounded-xl bg-fill px-3 text-[17px] outline-none placeholder:text-muted-foreground'
                />
                <button
                    type='button'
                    onClick={() => save.mutate()}
                    disabled={save.isPending || !settings.data}
                    className='min-h-11 w-full cursor-pointer rounded-xl bg-primary text-[17px] font-semibold disabled:opacity-50'
                >
                    Сохранить
                </button>
            </div>
        </Group>
    )
}
