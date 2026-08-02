export function parseStrictJson(text: string): unknown {
  let index = 0
  const whitespace = () => { while (/\s/.test(text[index] ?? '')) index++ }
  const string = (): string => {
    const start = index
    if (text[index++] !== '"') throw new Error('expected JSON string')
    while (index < text.length) {
      if (text[index] === '\\') { index += 2; continue }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index)) as string
    }
    throw new Error('unterminated JSON string')
  }
  const value = (): void => {
    whitespace()
    if (text[index] === '{') {
      index++; whitespace(); const keys = new Set<string>()
      if (text[index] === '}') { index++; return }
      while (index < text.length) {
        whitespace(); const key = string()
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`)
        keys.add(key); whitespace()
        if (text[index++] !== ':') throw new Error('expected JSON colon')
        value(); whitespace()
        const token = text[index++]
        if (token === '}') return
        if (token !== ',') throw new Error('expected JSON object delimiter')
      }
    } else if (text[index] === '[') {
      index++; whitespace()
      if (text[index] === ']') { index++; return }
      while (index < text.length) {
        value(); whitespace()
        const token = text[index++]
        if (token === ']') return
        if (token !== ',') throw new Error('expected JSON array delimiter')
      }
    } else if (text[index] === '"') string()
    else {
      const match = text.slice(index).match(/^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/)
      if (!match) throw new Error('invalid JSON token')
      index += match[0].length
    }
  }
  value(); whitespace()
  if (index !== text.length) throw new Error('trailing JSON content')
  return JSON.parse(text)
}
