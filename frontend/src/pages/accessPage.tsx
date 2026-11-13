import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Group, PageTitle, Row } from '@/components/ios'
import { api } from '@/lib/api'

type FaceIDAccess = {
    available: boolean
    status: 'unconfigured' | 'pending' | 'ready' | 'external'
    label?: string
    https_url?: string
    qr?: string
    message?: string
}

type PanelAccess = {
    url: string
    qr: string
    passkey_domain_configured: boolean
    face_id?: FaceIDAccess
}

type DomainPlan = { https_url: string; router_admin_public: boolean }

const accessKey = ['panel-access']
const labelKey = 'xkeen.face-id.domain-draft'
const validLabel = (value: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)

function initialLabel() {
    try {
        const previous = sessionStorage.getItem(labelKey)
        if (previous && validLabel(previous)) return previous
    } catch {}
    return 'xk-' + Array.from(crypto.getRandomValues(new Uint8Array(5)), byte => byte.toString(16).padStart(2, '0')).join('')
}

function AddressQR({ qr, alt }: { qr?: string; alt: string }) {
    if (!qr) return null
    return <div className='flex flex-col items-center gap-2 py-4'>
        <img src={qr} alt={alt} className='aspect-square w-56 max-w-full rounded-2xl border-8 border-white bg-white' />
        <p className='text-sm text-muted-foreground'>Отсканируйте камерой iPhone</p>
    </div>
}

function DomainSetup({ face }: { face: FaceIDAccess }) {
    const qc = useQueryClient()
    const [draft, setDraft] = useState(initialLabel)
    const [editing, setEditing] = useState(false)
    const [privateAdmin, setPrivateAdmin] = useState(false)
    const pending = face.status === 'pending'
    const label = face.label || draft
    const preview = useMutation({
        mutationFn: async (selected: string) => {
            const result = await api.get<DomainPlan>('/api/access/face-id/plan?label=' + encodeURIComponent(selected))
            const address = new URL(result.https_url)
            if (address.protocol !== 'https:' || address.username || address.password || typeof result.router_admin_public !== 'boolean') {
                throw new Error('Не удалось определить HTTPS-адрес и режим доступа роутера.')
            }
            return result
        },
    })
    const plan = preview.variables === label ? preview.data : undefined
    const prepare = useMutation({
        mutationFn: (selection: { label: string; expected_url: string; admin_access?: 'private' }) =>
            api.post<PanelAccess>('/api/access/face-id/prepare', selection),
        onSuccess: result => {
            qc.setQueryData(accessKey, result)
            setEditing(false)
            setPrivateAdmin(false)
            preview.reset()
            if (result.face_id?.status === 'ready') {
                try { sessionStorage.removeItem(labelKey) } catch {}
            }
        },
        onError: () => {
            preview.reset()
            setPrivateAdmin(false)
            void qc.invalidateQueries({ queryKey: accessKey })
        },
    })
    function checkPlan() {
        if (!validLabel(label) || preview.isPending) return
        setPrivateAdmin(false)
        prepare.reset()
        preview.mutate(label)
    }
    function submit() {
        if (prepare.isPending || !plan || (plan.router_admin_public && !privateAdmin)) return
        try { sessionStorage.setItem(labelKey, label) } catch {}
        prepare.mutate({ label, expected_url: plan.https_url, admin_access: plan.router_admin_public ? 'private' : undefined })
    }
    const busy = preview.isPending || prepare.isPending
    return <>
        {pending ? <Row label='Настройка HTTPS продолжается' hint={face.message || 'Роутер проверяет домен и сертификат. Статус обновляется каждые 10 секунд.'} />
            : <Row label='Настроить HTTPS для Face ID' hint='Для Safari нужен постоянный HTTPS-адрес панели в домашней сети. Роутер может получить его через CrazeDNS.' />}
        {(editing || pending) && <div className='space-y-3 py-3'>
            <label className='grid gap-1.5 text-sm font-medium'>Имя роутера в CrazeDNS
                <input className='min-h-11 min-w-0 w-full rounded-xl border border-white/10 bg-fill px-3 text-base outline-none focus:border-tint'
                    value={label} disabled={pending || !!face.label || busy} maxLength={63} autoComplete='off' autoCapitalize='none'
                    spellCheck={false} onChange={e => { setDraft(e.target.value.toLowerCase()); preview.reset(); prepare.reset(); setPrivateAdmin(false) }} />
            </label>
            {pending && <p className='text-sm text-muted-foreground'>Проверяем готовность каждые 10 секунд. Если статус долго не меняется, продолжите настройку с тем же именем.</p>}
            {!validLabel(label) && <p className='text-sm text-destructive'>Введите от 1 до 63 латинских букв, цифр или дефисов. На краях допустимы буква или цифра.</p>}
            {plan && <>
                <p className='text-sm text-muted-foreground'>После настройки панель будет доступна из домашней сети по адресу <strong className='break-all text-foreground'>{plan.https_url}</strong>.</p>
                <p className='text-sm text-muted-foreground'>Роутер использует свой зарегистрированный домен или запросит в CrazeDNS регистрацию имени <strong className='break-all text-foreground'>{label}</strong>. Панель настроит сертификат и привяжет ключи входа к HTTPS-адресу.</p>
                {plan.router_admin_public && <label className='flex min-h-11 items-start gap-3 rounded-xl bg-fill p-3 text-sm'>
                    <input type='checkbox' className='mt-0.5 size-5 shrink-0 accent-[var(--primary)]' checked={privateAdmin} disabled={busy}
                        onChange={e => setPrivateAdmin(e.target.checked)} />
                    <span>Отключить доступ из интернета к штатному веб-интерфейсу роутера. После этого управлять роутером через него можно будет из домашней сети.</span>
                </label>}
            </>}
        </div>}
        {(prepare.error || preview.error) && <p role='alert' className='break-words py-2 text-sm text-destructive'>{(prepare.error || preview.error)?.message}</p>}
        {pending || editing ? <>
            {plan ? <Row label={prepare.isPending ? 'Настраиваем HTTPS…' : 'Подтвердить настройку HTTPS'} tone='tint'
                disabled={busy || (plan.router_admin_public && !privateAdmin)} onClick={submit} />
                : <Row label={preview.isPending ? 'Проверяем адрес…' : pending ? 'Продолжить настройку' : 'Проверить адрес и параметры'} tone='tint'
                    disabled={busy || !validLabel(label)} onClick={checkPlan} />}
            {!pending && <Row label='Отмена' disabled={busy} onClick={() => { setEditing(false); preview.reset(); prepare.reset(); setPrivateAdmin(false) }} />}
        </> : <Row label='Подготовить адрес для iPhone' tone='tint' onClick={() => setEditing(true)} />}
    </>
}

function verifiedAddress(face?: FaceIDAccess) {
    if (face?.status !== 'ready' || !face.https_url) return
    try {
        const url = new URL(face.https_url)
        if (url.protocol === 'https:' && !url.username && !url.password) return url
    } catch {}
}

export function AccessPage() {
    const query = useQuery({
        queryKey: accessKey,
        queryFn: () => api.get<PanelAccess>('/api/access'),
        refetchInterval: state => state.state.data?.face_id?.status === 'pending' ? 10000 : false,
    })
    const { hash } = useLocation()
    useEffect(() => {
        if (hash === '#face-id') document.getElementById('face-id')?.scrollIntoView()
    }, [hash])
    const access = query.data
    const face = access?.face_id
    const ready = verifiedAddress(face)
    const secureHere = window.location.protocol === 'https:' && window.isSecureContext &&
        (ready ? window.location.origin === ready.origin : !!access?.passkey_domain_configured)
    return <>
        <PageTitle title='Вход с компьютера и телефона' back={{ to: '/settings', label: 'Настройки' }} />
        <div id='face-id'>
            <Group title='Face ID на iPhone'>
                {query.isLoading && <Row label='Проверяем HTTPS-адрес панели…' />}
                {ready ? <>
                    <Row label='HTTPS-адрес готов' hint='Откройте этот адрес в Safari, подключившись к домашнему Wi-Fi.' />
                    <a href={face!.https_url} className='block break-all py-3 text-[16px] font-semibold text-tint underline'>{face!.https_url}</a>
                    <AddressQR qr={face?.qr} alt='QR-код HTTPS-адреса панели для входа по Face ID' />
                </> : face?.available && (face.status === 'unconfigured' || face.status === 'pending') ? <DomainSetup face={face} />
                    : access && <Row label={face?.status === 'external' || access.passkey_domain_configured ? 'Для ключей входа задан домен' : 'Для Face ID нужен HTTPS-адрес'}
                        hint={face?.message || (access.passkey_domain_configured ? 'Откройте настроенный HTTPS-домен панели в Safari на iPhone.' : 'Для этой конфигурации задайте HTTPS-домен панели и доверенный сертификат.')} />}
                {query.error && <Row label='Не удалось проверить адрес' hint={query.error.message} tone='tint' onClick={() => void query.refetch()} />}
            </Group>
        </div>
        <Group title='Подключение в Safari' footer='При следующих входах откройте тот же HTTPS-адрес, нажмите «Войти по Face ID» и подтвердите вход на iPhone.'>
            <Row label='1. Подключите iPhone к домашнему Wi-Fi' hint='Откройте HTTPS-адрес панели в Safari.' />
            <Row label='2. Войдите с паролем и одноразовым кодом' />
            <Row label='3. В настройках нажмите «Включить вход по Face ID»' hint='Сохраните ключ доступа на iPhone и подтвердите действие по Face ID.' />
            {secureHere && <Row label='Открыть настройки панели' tone='tint' to='/settings' />}
        </Group>
        {(!ready || window.location.origin !== ready.origin) && <Group title='Локальный адрес панели' footer='Этот адрес работает в домашней сети. Для Face ID на iPhone используйте HTTPS-адрес.'>
            <Row label='Адрес панели' hint={<span className='break-all'>{access?.url ?? window.location.origin + '/'}</span>} />
            <AddressQR qr={access?.qr} alt='QR-код локального адреса панели' />
        </Group>}
        <Group title='На компьютере'><Row label='1. Подключитесь к домашней сети' /><Row label='2. Откройте адрес панели в браузере' /><Row label='3. Сохраните страницу в закладки' /></Group>
        <Group title='На iPhone' footer='Значок веб-приложения открывает панель в домашней сети.'>
            <Row label='1. Откройте панель в Safari' />
            <Row label='2. Нажмите «Поделиться»' />
            <Row label='3. Выберите «На экран Домой»' />
            <Row label='4. Нажмите «Добавить»' hint='Если видите переключатель «Открывать как веб-приложение», включите его.' />
        </Group>
        <Group title='На Android'><Row label='Откройте панель в браузере' hint='В меню браузера выберите «Добавить на главный экран» или «Установить приложение», если такой пункт доступен.' /></Group>
    </>
}
