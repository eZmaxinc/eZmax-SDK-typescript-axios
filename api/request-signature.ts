declare var require: any
var forge = require('node-forge')
var utf8 = require('utf8')

  
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
    
    const md = forge.md.sha256.create()
    md.update(contentToHash)

    const ouput = md.digest().toHex()
    
    return 'v1=' + ouput
  }

  public static getSignature(signatureData: ISignatureData): string {
    const contentToSign = `${signatureData.fingerprint}${signatureData.authorization}${signatureData.date}`

    const hmac = forge.hmac.create()
    hmac.start('sha256', signatureData.secret)
    hmac.update(contentToSign)
  
    return 'v1=' + hmac.digest().toHex()
  }

  public static getHeaders(headerData: IHeadersData) {
    const date = new Date()
    const isoDate = date.toISOString().split('.')[0] + 'Z'

    const fingerprint: string = this.getFingerprint({
      authorization: headerData.authorization,
      date: isoDate,
      method: headerData.method,
      url: headerData.url,
      body: utf8.encode(headerData.body),
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
