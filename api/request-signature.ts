import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { bytesToHex } from '@noble/hashes/utils.js'

export interface IFingerprintData {
  authorization: string
  date: string
  method: string
  url: string
  body: string
  expiration?: number
}

export interface ISignatureData {
  authorization: string
  date: string
  fingerprint: string
  secret: string
}

export interface IHeadersData {
  authorization: string
  secret: string
  method: string
  url: string
  body: string
  expiration?: number
}

export class RequestSignature {
  public static getFingerprint(fingerprintData: IFingerprintData): string {
    const expiration = fingerprintData.expiration ? `\n${fingerprintData.expiration}` : ''
    const contentToHash = `${fingerprintData.method}\n${fingerprintData.url}\n${fingerprintData.body}\n${fingerprintData.authorization}\n${fingerprintData.date}${expiration}`
    
    const output = bytesToHex(sha256(new TextEncoder().encode(contentToHash)))
    
    return 'v1=' + output
  }

  public static getSignature(signatureData: ISignatureData): string {
    const contentToSign = `${signatureData.fingerprint}${signatureData.authorization}${signatureData.date}`
    const encoder = new TextEncoder()

    const output = bytesToHex(hmac(sha256, encoder.encode(signatureData.secret), encoder.encode(contentToSign)))
  
    return 'v1=' + output
  }

  public static getHeaders(headerData: IHeadersData) {
    const date = new Date()
    const isoDate = date.toISOString().split('.')[0] + 'Z'

    const fingerprint: string = this.getFingerprint({
      authorization: headerData.authorization,
      date: isoDate,
      method: headerData.method,
      url: headerData.url,
      body: headerData.body,
      expiration: headerData.expiration
    })

    const signature: string = this.getSignature({
      authorization: headerData.authorization,
      date: isoDate,
      fingerprint: fingerprint,
      secret: headerData.secret
    })

    return {
      'Ezmax-Date': isoDate,
      'Ezmax-Fingerprint': fingerprint,
      'Ezmax-Signature': signature,
      ...(headerData.expiration) ? { 'Ezmax-Expiration': headerData.expiration } : {}
    }
  }
}
