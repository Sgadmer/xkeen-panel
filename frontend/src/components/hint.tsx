import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

const canHover = () => typeof window !== 'undefined' && window.matchMedia?.('(hover: hover)').matches

// A small control that explains itself: on a computer the text shows on
// hover, on a phone a tap opens it. The tap never reaches the row beneath, so
// reading a hint does not select a server.
export function Hint({ label, content, children, round = true, className }: {
    label: string
    // What the bubble shows when it needs more than plain text; label stays
    // the text for screen readers.
    content?: ReactNode
    children: ReactNode
    round?: boolean
    className?: string
}) {
    const [open, setOpen] = useState(false)
    const [align, setAlign] = useState<'center' | 'left' | 'right'>('center')
    const box = useRef<HTMLSpanElement>(null)

    useEffect(() => {
        if (!open) return
        const outside = (event: Event) => {
            if (!box.current?.contains(event.target as Node)) setOpen(false)
        }
        const escape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') setOpen(false)
        }
        document.addEventListener('pointerdown', outside)
        document.addEventListener('keydown', escape)
        return () => {
            document.removeEventListener('pointerdown', outside)
            document.removeEventListener('keydown', escape)
        }
    }, [open])

    const show = () => {
        // Keep the bubble on screen next to the left or right edge.
        const rect = box.current?.getBoundingClientRect()
        if (rect) setAlign(rect.left < 140 ? 'left' : window.innerWidth - rect.right < 140 ? 'right' : 'center')
        setOpen(true)
    }

    return (
        <span ref={box} className='relative inline-flex'
            onMouseEnter={() => canHover() && show()}
            onMouseLeave={() => canHover() && setOpen(false)}>
            <button type='button' aria-label={label} aria-expanded={open}
                onClick={event => {
                    event.stopPropagation()
                    if (open) setOpen(false)
                    else show()
                }}
                className={cn('pointer-events-auto relative z-10 inline-flex cursor-help items-center justify-center focus-visible:outline-2 focus-visible:outline-tint',
                    round && 'size-[22px] rounded-full bg-secondary text-secondary-foreground',
                    className)}>
                {children}
            </button>
            {open && (
                <span role='tooltip'
                    className={cn('absolute bottom-full z-30 mb-1.5 w-max max-w-[15rem] rounded-lg border border-white/10 bg-popover px-2.5 py-1.5 text-left text-[13px] font-normal leading-snug tracking-normal text-popover-foreground shadow-lg',
                        align === 'center' && 'left-1/2 -translate-x-1/2',
                        align === 'left' && 'left-0',
                        align === 'right' && 'right-0')}>
                    {content ?? label}
                </span>
            )}
        </span>
    )
}
