import { useQuery } from '@tanstack/react-query'
import { Group, PageTitle, Row } from '@/components/ios'
import { api } from '@/lib/api'

export function AccessPage() {
    const query = useQuery({ queryKey: ['panel-access'], queryFn: () => api.get<{url: string; qr: string}>('/api/access') })
    return <>
        <PageTitle title='Вход с компьютера и телефона' back={{to:'/settings',label:'Настройки'}} />
        <Group title='Ваш адрес панели' footer='Локальный адрес работает, когда устройство подключено к домашней сети роутера. Для входа используйте свою учётную запись панели.'>
            <Row label='Открыть в браузере' detail={query.data?.url ?? window.location.origin + '/'} />
            {query.data && <div className='flex flex-col items-center gap-3 py-5'><img src={query.data.qr} alt='QR-код адреса панели без паролей и ключей' className='size-56 rounded-2xl border-8 border-white bg-white' /><p className='text-sm text-muted-foreground'>Отсканируйте камерой телефона</p></div>}
            {query.error && <Row label='QR-код пока недоступен' hint={query.error.message} />}
        </Group>
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
