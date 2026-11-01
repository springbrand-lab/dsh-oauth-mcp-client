import { Context } from '@deepseek-ai/cordis'
import type { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { describe, expect, it, vi } from 'vitest'
import { resolveConfig } from '../src/index.js'
import { createOAuthRuntime } from '../src/oauth.js'

const config = resolveConfig({
  serverName: 'test',
  url: 'https://mcp.example.com/mcp',
  authorizationTimeoutMs: 2_000,
})

describe('OAuth loopback flow', () => {
  it('rejects a forged state and exchanges a valid callback code', async () => {
    const ctx = new Context()

    const rejected = await createOAuthRuntime(ctx, config, async () => {})
    try {
      const state = String(await rejected.provider.state?.())
      await rejected.provider.redirectToAuthorization(new URL(`https://auth.example.com/?state=${state}`))
      const callback = new URL(rejected.provider.redirectUrl!)
      callback.search = new URLSearchParams({ code: 'forged', state: 'wrong' }).toString()
      expect((await fetch(callback)).status).toBe(400)
      await expect(rejected.waitForAuthorization()).rejects.toThrow('state does not match')
    } finally {
      await rejected.dispose()
    }

    const opened: URL[] = []
    const accepted = await createOAuthRuntime(ctx, config, async url => { opened.push(url) })
    const finishAuth = vi.fn(async (_code: string) => {})
    accepted.bindTransport({ finishAuth } as unknown as StreamableHTTPClientTransport)
    try {
      const state = String(await accepted.provider.state?.())
      const authorizationUrl = new URL(`https://auth.example.com/?state=${state}`)
      await accepted.provider.redirectToAuthorization(authorizationUrl)
      expect(opened).toEqual([authorizationUrl])

      const callback = new URL(accepted.provider.redirectUrl!)
      callback.search = new URLSearchParams({ code: 'valid-code', state }).toString()
      const wait = accepted.waitForAuthorization()
      expect((await fetch(callback)).status).toBe(200)
      await wait
      expect(finishAuth).toHaveBeenCalledWith('valid-code')
    } finally {
      await accepted.dispose()
    }
  })
})

describe('OAuth callback hardening', () => {
  /** Start a runtime with a pending authorization and a bound transport whose exchange is observable. */
  async function pending(timeoutMs = 2_000) {
    const cfg = timeoutMs === 2_000
      ? config
      : resolveConfig({ serverName: 'test', url: 'https://mcp.example.com/mcp', authorizationTimeoutMs: timeoutMs })
    const runtime = await createOAuthRuntime(new Context(), cfg, async () => {})
    const finishAuth = vi.fn(async (_code: string) => {})
    runtime.bindTransport({ finishAuth } as unknown as StreamableHTTPClientTransport)
    const state = String(await runtime.provider.state?.())
    await runtime.provider.redirectToAuthorization(new URL(`https://auth.example.com/?state=${state}`))
    return { runtime, finishAuth, state }
  }

  /** Build a callback URL on the runtime's own loopback origin. */
  function callback(runtime: Awaited<ReturnType<typeof pending>>['runtime'], params: Record<string, string>, path = '/oauth/callback') {
    const url = new URL(path, runtime.provider.redirectUrl!)
    url.search = new URLSearchParams(params).toString()
    return url
  }

  it('binds the callback listener to 127.0.0.1', async () => {
    const { runtime } = await pending()
    try {
      expect(new URL(runtime.provider.redirectUrl!).hostname).toBe('127.0.0.1')
    } finally {
      await runtime.dispose()
    }
  })

  it('rejects a callback without state', async () => {
    const { runtime } = await pending()
    try {
      const rejection = expect(runtime.waitForAuthorization()).rejects.toThrow('state is missing')
      expect((await fetch(callback(runtime, { code: 'abc' }))).status).toBe(400)
      await rejection
    } finally {
      await runtime.dispose()
    }
  })

  it('rejects a callback without code', async () => {
    const { runtime, state } = await pending()
    try {
      const rejection = expect(runtime.waitForAuthorization()).rejects.toThrow('code is missing')
      expect((await fetch(callback(runtime, { state }))).status).toBe(400)
      await rejection
    } finally {
      await runtime.dispose()
    }
  })

  it('fails the flow on an OAuth error callback', async () => {
    const { runtime, state } = await pending()
    try {
      const rejection = expect(runtime.waitForAuthorization()).rejects.toThrow('access_denied')
      expect((await fetch(callback(runtime, { error: 'access_denied', state }))).status).toBe(400)
      await rejection
    } finally {
      await runtime.dispose()
    }
  })

  it('answers 404 outside the callback path and leaves the flow pending', async () => {
    const { runtime } = await pending()
    try {
      const rejection = expect(runtime.waitForAuthorization()).rejects.toThrow('disposed during authorization')
      expect((await fetch(callback(runtime, { code: 'abc', state: 's' }, '/not-oauth'))).status).toBe(404)
      await runtime.dispose()
      await rejection
    } finally {
      await runtime.dispose()
    }
  })

  it('does not accept a replayed callback', async () => {
    const { runtime, state, finishAuth } = await pending()
    try {
      const url = callback(runtime, { code: 'once', state })
      const wait = runtime.waitForAuthorization()
      expect((await fetch(url)).status).toBe(200)
      await wait
      expect(finishAuth).toHaveBeenCalledTimes(1)
      expect((await fetch(url)).status).toBe(409)
      expect(finishAuth).toHaveBeenCalledTimes(1)
    } finally {
      await runtime.dispose()
    }
  })

  it('ends an unanswered authorization on timeout', async () => {
    const { runtime } = await pending(50)
    try {
      await expect(runtime.waitForAuthorization()).rejects.toThrow('timed out')
    } finally {
      await runtime.dispose()
    }
  })
})
