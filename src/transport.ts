/** OAuth-aware Streamable HTTP transport factory. */

import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import type { ResolvedConfig } from './index.js'
import type { OAuthRuntime } from './oauth.js'

/** Create a transport and bind its authorization-code exchange to the callback runtime. */
export function createTransport(
  config: ResolvedConfig,
  oauth: OAuthRuntime,
): Transport {
  const transport = new StreamableHTTPClientTransport(new URL(config.url), {
    authProvider: oauth.provider,
    // 钉住 SDK 1.32.0 起的安全默认:只跟随同源重定向,跨源重定向直接失败,
    // 避免 Authorization、Bearer token 与自定义 header 被转发到其他 origin。
    redirectPolicy: 'same-origin',
    requestInit: { headers: config.headers },
  })
  oauth.bindTransport(transport)
  return transport as Transport
}
