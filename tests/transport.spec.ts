import { createServer, type RequestListener, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { afterEach, describe, expect, it } from 'vitest'
import { resolveConfig } from '../src/index.js'
import type { OAuthRuntime } from '../src/oauth.js'
import { createTransport } from '../src/transport.js'

/** A provider whose OAuth state is irrelevant: these tests exercise transport redirect handling only. */
function inertOAuth(): OAuthRuntime {
  const provider = {
    clientMetadata: {
      redirect_uris: ['http://127.0.0.1:1/oauth/callback'],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      client_name: 'transport-test',
    },
    state: () => 'state',
    clientInformation: () => undefined,
    saveClientInformation: () => {},
    tokens: () => undefined,
    saveTokens: () => {},
    redirectToAuthorization: async () => {},
    saveCodeVerifier: () => {},
    codeVerifier: () => 'verifier',
    saveDiscoveryState: () => {},
    discoveryState: () => undefined,
    invalidateCredentials: async () => {},
  } as unknown as OAuthClientProvider
  return {
    provider,
    bindTransport: () => {},
    waitForAuthorization: async () => {},
    dispose: async () => {},
  }
}

const servers: Server[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => {
    server.close(() => { resolve() })
  })))
})

/** Listen on an OS-assigned loopback port and return it. */
async function listen(handler: RequestListener): Promise<number> {
  const server = createServer(handler)
  servers.push(server)
  await new Promise<void>(resolve => { server.listen(0, '127.0.0.1', () => { resolve() }) })
  return (server.address() as AddressInfo).port
}

/** Answer one MCP initialize request with the protocol version the client proposed. */
function answerInitialize(body: string, response: import('node:http').ServerResponse): void {
  const request = JSON.parse(body) as { id?: unknown; params?: { protocolVersion?: unknown } }
  response.writeHead(200, { 'content-type': 'application/json' })
  response.end(JSON.stringify({
    jsonrpc: '2.0',
    id: request.id,
    result: {
      protocolVersion: request.params?.protocolVersion ?? '2025-06-18',
      capabilities: {},
      serverInfo: { name: 'transport-test', version: '1.0.0' },
    },
  }))
}

describe('transport configuration guards', () => {
  it('refuses an Authorization header and non-loopback plain HTTP endpoints', () => {
    expect(() => resolveConfig({
      serverName: 'test',
      url: 'https://mcp.example.com/mcp',
      headers: { Authorization: 'Bearer hand-made' },
    })).toThrow(/Authorization is owned by OAuth/)

    expect(() => resolveConfig({
      serverName: 'test',
      url: 'https://mcp.example.com/mcp',
      headers: { authorization: 'bearer lower-case' },
    })).toThrow(/Authorization is owned by OAuth/)

    expect(() => resolveConfig({ serverName: 'test', url: 'http://mcp.example.com/mcp' }))
      .toThrow(/must use HTTPS/)

    expect(() => resolveConfig({ serverName: 'test', url: 'http://127.0.0.1:3000/mcp' })).not.toThrow()
  })
})

describe('redirect policy', () => {
  it('refuses a cross-origin redirect and never contacts the other origin', async () => {
    let foreignHits = 0
    const foreignPort = await listen((_request, response) => {
      foreignHits += 1
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end('{}')
    })
    const endpointPort = await listen((_request, response) => {
      response.writeHead(307, { location: `http://127.0.0.1:${foreignPort}/mcp` })
      response.end()
    })

    const config = resolveConfig({ serverName: 'test', url: `http://127.0.0.1:${endpointPort}/mcp` })
    const client = new Client({ name: 'transport-test', version: '1.0.0' }, { capabilities: {} })
    await expect(client.connect(createTransport(config, inertOAuth())))
      .rejects.toThrow(/redirectPolicy: 'same-origin'/)
    expect(foreignHits).toBe(0)
  })

  it('still follows a redirect that stays on the same origin', async () => {
    let initializeServed = false
    const port = await listen((request, response) => {
      if (request.url === '/mcp') {
        response.writeHead(307, { location: '/mcp-session' })
        response.end()
        return
      }
      let body = ''
      request.on('data', chunk => { body += String(chunk) })
      request.on('end', () => {
        initializeServed = true
        answerInitialize(body, response)
      })
    })

    const config = resolveConfig({ serverName: 'test', url: `http://127.0.0.1:${port}/mcp` })
    const client = new Client({ name: 'transport-test', version: '1.0.0' }, { capabilities: {} })
    await client.connect(createTransport(config, inertOAuth()))
    expect(initializeServed).toBe(true)
    await client.close()
  })
})
