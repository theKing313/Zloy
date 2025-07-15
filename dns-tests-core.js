import { ipData, getIPData } from 'https://dnst.lat/js/ip-tests-core.js'

// Shared state
export let clientId
export const clientSubnets = {}
export const resolvers = {}
export const dnssecTests = [...Array(12)]
export const rtts = []
export const udpSizes = []
export let count = 0
export let seenIPv6 = false

// Initialize or reset state
export function initDnsState(customClientId) {
  // Use provided clientId or generate a random one
  clientId = customClientId || Math.floor(Math.random() * 0xffffffff).toString(16)
  
  // Clear all data collections
  Object.keys(clientSubnets).forEach(key => delete clientSubnets[key])
  Object.keys(resolvers).forEach(key => delete resolvers[key])
  
  // Reset arrays and counters
  dnssecTests.fill(undefined)
  rtts.length = 0
  udpSizes.length = 0
  count = 0
  seenIPv6 = false
  
  return clientId
}

// Core testing functions
export const makeQuery = (subdomain, timeout, abortSignal) => {
  if (abortSignal.aborted) {
    return Promise.resolve(false)
  }
  const controller = new AbortController()
  const abortFn = () => controller.abort()
  const timeoutID = setTimeout(abortFn, timeout)
  abortSignal.addEventListener('abort', abortFn)
  return fetch(`https://${subdomain}.dnst.lat/`, { signal: controller.signal })
    .then(r => r.ok, () => false)
    .finally(() => {
      clearTimeout(timeoutID)
      abortSignal.removeEventListener('abort', abortFn)
    })
}

export const testDNS = (callbacks = {}) => {
  const { 
    onNewResolver, 
    onResolverUpdate, 
    onDnssecUpdate, 
    onSubnetFound,
    onSubnetUpdate,
    onIpv6Found,
    onEdnsUpdate,
    onTcpStatusUpdate,
    onCountUpdate
  } = callbacks
  
  return new Promise(done => {
    // WebSocket for watching DNS requests
    const socket = new WebSocket(`wss://dnst.lat/watch/${clientId}`)
    const abortController = new AbortController()
    
    socket.addEventListener('open', async () => {
      console.log('WebSocket opened')
      
      // Generate DNS requests
      for (let i = 0; i < 5; i++) {
        await makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go`, 10000, abortController.signal)
        await makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go-ipv4`, 10000, abortController.signal)
      }
      
      // Test IPv6 support
      if (!seenIPv6) {
        await makeQuery(`${clientId}-nullip.go-ipv6`, 10000, abortController.signal)
      }
      
      if (!seenIPv6 && onIpv6Found) {
        onIpv6Found(false)
      }
      
      // Test TCP fallback
      const usesTCP = await makeQuery(`${clientId}-truncate.go`, 10000, abortController.signal)
      if (!usesTCP && onTcpStatusUpdate) {
        onTcpStatusUpdate(false)
      }
      
      // Test DNSSEC validation
      for (const [algIndex, alg] of ['alg13', 'alg14', 'alg15'].entries()) {
        await Promise.all(['', '-badsig', '-expiredsig', '-nosig'].map(
          (sigOpt, sigIndex) => makeQuery(`${clientId}${sigOpt}.go-${alg}`, 30000, abortController.signal).then(
            got => {
              dnssecTests[4 * algIndex + sigIndex] = got
              if (onDnssecUpdate) onDnssecUpdate(dnssecTests)
            }
          )
        ))
      }
      
      // Close websocket after delay
      setTimeout(() => {
        if (socket.readyState === 1) {
          socket.close(1000)
        }
      }, 10000)
      
      done()
    })
    
    socket.addEventListener('message', ({ data }) => {
      // Parse data
      const request = JSON.parse(data)
      
      // Increment count
      count++
      if (onCountUpdate) onCountUpdate(count)
      
      // Add resolver if new
      if (resolvers[request.remoteIp] === undefined) {
        resolvers[request.remoteIp] = {
          str: request.remoteIp,
          pending: true,
          requests: [],
        }
        
        if (onNewResolver) onNewResolver(resolvers[request.remoteIp])
        
        getIPData(request.remoteIp).then(data => {
          const { requests } = resolvers[request.remoteIp]
          resolvers[request.remoteIp] = { ...data, requests }
          
          if (onResolverUpdate) onResolverUpdate(resolvers[request.remoteIp])
        })
      }
      
      // Add request
      resolvers[request.remoteIp].requests.push(request)
      
      // Discover EDNS support
      if (request.isEdns0 && !udpSizes.includes(request.udpSize)) {
        udpSizes.push(request.udpSize)
        udpSizes.sort((a, b) => a - b)
        
        if (onEdnsUpdate) onEdnsUpdate(udpSizes)
      }
      
      if (count === 1 && udpSizes.length === 0 && onEdnsUpdate) {
        onEdnsUpdate([])
      }
      
      // Discover ECS
      if (request.clientSubnet && !request.clientSubnet.endsWith('/0') && clientSubnets[request.clientSubnet] === undefined) {
        clientSubnets[request.clientSubnet] = {
          str: request.clientSubnet,
          pending: true,
        }
        
        if (onSubnetFound) onSubnetFound(clientSubnets[request.clientSubnet])
        
        getIPData(request.clientSubnet).then(data => {
          clientSubnets[request.clientSubnet] = data
          
          if (onSubnetUpdate) onSubnetUpdate(data)
        })
      }
      
      // Discover IPv6 support
      if (!seenIPv6 && request.remoteIp.includes(':')) {
        seenIPv6 = true
        
        if (onIpv6Found) onIpv6Found(true)
      }
    })
    
    socket.addEventListener('close', e => {
      abortController.abort()
      console.log('WebSocket closed', e)
    })
  })
}

export const testRTT = async (callbacks = {}) => {
  const { onRttUpdate } = callbacks
  
  let rand, start, avg
  for (let i = 0; i < 5; i++) {
    for (const tld of ['com', 'net', 'org']) {
      rand = Math.random().toString(36).slice(2)
      start = Date.now()
      await fetch(`https://test-${rand}.null-addr.${tld}/`).catch(() => {})
      rtts.push(Date.now() - start)
      avg = Math.round(rtts.reduce((sum, x) => sum + x) / rtts.length)
      
      if (onRttUpdate) onRttUpdate(avg)
    }
  }
}

// Main function to run dns tests with optional clientId
export const runDnsTests = async (options = {}) => {
  const { 
    customClientId,
    callbacks = {}
  } = options
  
  // Initialize state with provided clientId or generate new one
  initDnsState(customClientId)
  
  // Run tests
  await testDNS(callbacks)
  await Promise.allSettled(Object.values(ipData))
  await testRTT(callbacks)
  
  return {
    clientId,
    clientSubnets,
    resolvers,
    dnssecTests,
    rtts, 
    udpSizes,
    seenIPv6,
    count
  }
}

// Helper function to convert BigInt values to strings recursively
const convertBigIntValues = (obj) => {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }
  
  if (Array.isArray(obj)) {
    return obj.map(convertBigIntValues)
  }
  
  // Handle IPAddr and IPRange objects specially - use their toString() methods
  if (obj.constructor?.name === 'IPAddr') {
    return obj.toString(true) // Use short IPv6 format
  }
  
  if (obj.constructor?.name === 'IPRange') {
    return obj.toString(true) // Use short IPv6 format
  }
  
  const cleaned = {}
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'bigint') {
      // Convert BigInt to string
      cleaned[key] = value.toString()
    } else if (typeof value === 'object' && value !== null) {
      cleaned[key] = convertBigIntValues(value)
    } else {
      cleaned[key] = value
    }
  }
  
  return cleaned
}

// Exported function to get DNS test results
export const getDnsTestsResult = async (options = {}) => {

  // Run DNS tests with the provided clientId
  const result = await runDnsTests(options)

  // Make requests Array at the top level
  // to populate it with the requests from each resolver later
  result.requests = []

  // Move requests to the top level
  Object.values(result.resolvers).forEach(resolver => {
    result.requests.push(...resolver.requests)
    delete resolver.requests
  })

  // Clean the entire result object to convert BigInt values to strings
  const cleanedResult = convertBigIntValues(result)

  // Make human readable object-like table of DNSSEC tests
  const dnssecTests = {}
  
  // Validate that we have the expected number of test results
  if (cleanedResult.dnssecTests.length === 12) {
    const algorithms = ['ECDSA P-256', 'ECDSA P-384', 'Ed25519']
    const signatureTypes = ['Good', 'Bad', 'Expired', 'Missing']
    
    // Populate the dnssecTests with structured data
    algorithms.forEach((alg, algIndex) => {
      dnssecTests[alg] = {}
      
      signatureTypes.forEach((sigType, sigIndex) => {
        // Calculate the index in the original array
        const arrayIndex = (algIndex * 4) + sigIndex
        
        // Get the test result
        const testResult = cleanedResult.dnssecTests[arrayIndex]
        
        // Set expected value - only "Good" signatures should pass
        const expected = sigIndex === 0
        
        // Store the test result
        dnssecTests[alg][sigType] = {
          result: testResult,
          expected: expected,
          pass: testResult === expected
        }
      })
    })
    
    // Replace the linear array with the structured object
    cleanedResult.dnssecTests = dnssecTests
  } else {
    console.warn(`Expected 12 DNSSEC test results, got ${cleanedResult.dnssecTests.length}`)
    // Provide an empty or partial structure to avoid undefined errors
    cleanedResult.dnssecTests = { error: "Incomplete test data" }
  }
  
  return cleanedResult
}