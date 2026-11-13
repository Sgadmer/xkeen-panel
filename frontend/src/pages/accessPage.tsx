import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { Group, PageTitle, Row } from '@/components/ios'
import { api } from '@/lib/api'

export function AccessPage() {
    const query = useQuery({ queryKey: ['panel-access'], queryFn: () => api.get<{url: string; qr: string; passkey_domain_configured: boolean}>('/api/access') })
    const { hash } = useLocation()
    useEffect(() => {
        if (hash === '#face-id') document.getElementById('face-id')?.scrollIntoView()
    }, [hash])
    return <>
        <PageTitle title='Вход с компьютера и телефона' back={{to:'/settings',label:'Настройки'}} />
        <Group title='Ваш адрес панели' footer='Локальный адрес работает, когда устройство подключено к домашней сети роутера. Для входа используйте свою учётную запись панели.'>
            <Row label='Открыть в браузере' detail={query.data?.url ?? window.location.origin + '/'} />
            {query.data && <div className='flex flex-col items-center gap-3 py-5'><img src={query.data.qr} alt='QR-код адреса панели без паролей и ключей' className='size-56 rounded-2xl border-8 border-white bg-white' /><p className='text-sm text-muted-foreground'>Отсканируйте камерой телефона</p></div>}
            {query.error && <Row label='QR-код пока недоступен' hint={query.error.message} />}
        </Group>
        <div id='face-id'>
            <Group title='Face ID для входа в панель' footer='При следующем входе с того же HTTPS-адреса нажмите «Войти через passkey» и подтвердите вход по Face ID.'>
                <Row label='1. Откройте HTTPS-адрес панели в Safari' hint={query.data?.passkey_domain_configured === false
                    ? 'Для этой панели ещё нужно настроить HTTPS с сертификатом, которому доверяет iPhone, и указать домен для ключей входа. На текущем HTTP-адресе Face ID недоступен.'
                    : 'Нужны доменное имя и сертификат, которому доверяет iPhone. По локальному HTTP-адресу создать ключ входа нельзя.'} />
                <Row label='2. Войдите в панель с паролем и одноразовым кодом' />
                <Row label='3. В настройках нажмите «Включить вход по Face ID»' hint='Сохраните ключ входа на iPhone и подтвердите действие по Face ID.' />
            </Group>
        </div>
        <Group title='На компьютере'><Row label='1. Подключитесь к домашней сети' /><Row label='2. Откройте адрес панели в браузере' /><Row label='3. Сохраните страницу в закладки' /></Group>
        <Group title='На iPhone' footer='Название и расположение кнопок могут немного отличаться в разных версиях iOS. Значок веб-приложения также открывает домашнюю панель и требует доступа к её адресу.'>
            <Row label='1. Подключите iPhone к домашнему Wi-Fi' />
            <Row label='2. Откройте панель в Safari' />
            <Row label='3. Нажмите «Поделиться»' />
            <Row label='4. Выберите «На экран Домой»' />
            <Row label='5. Включите «Открывать как веб-приложение»' hint='Если этот переключатель присутствует, затем нажмите «Добавить».' />
        </Group>
        <Group title='На Android'><Row label='Откройте панель в браузере' hint='В меню браузера выберите «Добавить на главный экран» или «Установить приложение», если такой пункт доступен.' /></Group>
    </>
}
