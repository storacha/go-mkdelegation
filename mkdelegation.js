// node mkdelegate.js <private-key>
import { delegate } from '@ucanto/core'
import * as ed25519 from '@ucanto/principal/ed25519'
import * as Link from 'multiformats/link'
import { identity } from 'multiformats/hashes/identity'
import { base64 } from 'multiformats/bases/base64'
import * as DID from '@ipld/dag-ucan/did'

const indexingServiceDID = 'did:key:z6Mkeb6qNxULhj6cUcxr4xLcyXSqNGAPZ8Se6yx5YJbvUpaD'
const uploadServiceDID = 'did:web:frrist.up.storacha.network'
const storageProviderDID = 'did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e'

const delegateIndexingServiceToUploadService = async () => {
  const issuer = ed25519.parse(process.argv[2]).withDID(indexingServiceDID)
  const audience = DID.parse(uploadServiceDID)
  const abilities = ['assert/equals', 'assert/index']

  const delegation = await delegate({
    issuer,
    audience,
    capabilities: abilities.map(can => ({ can, with: issuer.did(), nb: {} })),
    expiration: Infinity
  })

  console.log(await formatDelegation(delegation))
}

delegateIndexingServiceToUploadService()

const delegateStorageProviderToUploadService = async () => {
  const issuer = ed25519.parse(process.argv[2])
  const audience = DID.parse(uploadServiceDID)
  const abilities = ['blob/allocate', 'blob/accept']

  const delegation = await delegate({
    issuer,
    audience,
    capabilities: abilities.map(can => ({ can, with: issuer.did(), nb: {} })),
    expiration: Infinity
  })
  
  console.log(await formatDelegation(delegation))
}

// delegateStorageProviderToUploadService()

const delegateIndexingServiceToStorageProvider = async () => {
  const issuer = ed25519.parse(process.argv[2]).withDID(indexingServiceDID)
  const audience = DID.parse(storageProviderDID)
  const abilities = ['claim/cache']

  const delegation = await delegate({
    issuer,
    audience,
    capabilities: abilities.map(can => ({ can, with: issuer.did(), nb: {} })),
    expiration: Infinity
  })

  console.log(await formatDelegation(delegation))
}

// delegateIndexingServiceToStorageProvider()

/** @param {import('@ucanto/interface').Delegation} */
const formatDelegation = async delegation => {
  const { ok: archive, error } = await delegation.archive()
  if (error) throw error

  const digest = identity.digest(archive)
  const link = Link.create(0x0202, digest)
  return link.toString(base64)
}

