import { IconBrain, IconWorld } from '@tabler/icons-react'
import { cn } from '@/lib/utils'

const brands = new Set([
    'amazon', 'claude', 'discord', 'disney', 'facebook', 'github', 'google', 'hbo',
    'hulu', 'instagram', 'line', 'netflix', 'openai', 'playstation', 'primevideo',
    'spotify', 'steam', 'telegram', 'twitch', 'twitter', 'whatsapp', 'xbox', 'youtube',
])
const monochrome = new Set(['github', 'hbo', 'openai', 'twitter'])
const lightArtwork = new Set(['amazon', 'primevideo'])

export function ServiceLogo({ id, className }: { id: string; className?: string }) {
    if (!brands.has(id)) {
        const Glyph = id === 'ai' ? IconBrain : IconWorld
        return <Glyph aria-hidden className={cn('shrink-0 text-tint', className)} stroke={1.8} />
    }

    const classes = cn('block shrink-0 object-contain', className, id === 'line' && 'max-sm:size-10')
    const path = '/service-logos/' + id
    if (lightArtwork.has(id)) {
        return <>
            <img alt='' className={cn(classes, 'dark:hidden')} src={path + '.svg'} />
            <img alt='' className={cn(classes, 'hidden dark:block')} src={path + '-light.svg'} />
        </>
    }
    return <img alt='' className={cn(classes, monochrome.has(id) && 'dark:invert')}
        src={path + (id === 'line' ? '.png' : '.svg')} />
}
