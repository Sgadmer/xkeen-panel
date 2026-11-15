// This group has a fixed display order and is excluded from manual ordering.
export const aiServiceIds = ['claude', 'openai', 'ai', 'analytics'] as const
export function isAiService(id: string) { return aiServiceIds.some(item => item === id) }
