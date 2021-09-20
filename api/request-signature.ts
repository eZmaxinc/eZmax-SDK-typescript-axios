declare var require: any
var forge = require('node-forge')

  
export interface IFingerprintData {
  authorization: string
  date: string
  method: string
  url: string
  body: string
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
}

export class RequestSignature {
  public static getFingerprint(fingerprintData: IFingerprintData): string {
    const contentToHash = `${fingerprintData.method}\n${fingerprintData.url}\n${fingerprintData.body}\n${fingerprintData.authorization}\n${fingerprintData.date}`
    
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
      body: headerData.body
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
      'Ezmax-Signature': signature
    }
  }
}
