/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { WebhookheaderResponse } from './webhookheader-response';

/**
 * @type WebhookheaderResponseCompound
 * A Webhookheader Object
 * @export
 */
/*export type WebhookheaderResponseCompound = WebhookheaderResponse;*/
export interface WebhookheaderResponseCompound {
    /**
     * The unique ID of the Webhookheader
     * @type {number}
     * @memberof WebhookheaderResponseCompound
     */
    pkiWebhookheaderID:number 
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof WebhookheaderResponseCompound
     */
    fkiWebhookID:number 
    /**
     * The Name of the Webhookheader
     * @type {string}
     * @memberof WebhookheaderResponseCompound
     */
    sWebhookheaderName:string 
    /**
     * The Value of the Webhookheader
     * @type {string}
     * @memberof WebhookheaderResponseCompound
     */
    sWebhookheaderValue:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookheaderResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookheaderResponseCompound
 */
export class DataObjectWebhookheaderResponseCompound {
    pkiWebhookheaderID:number = 0
    fkiWebhookID:number = 0
    sWebhookheaderName:string = ''
    sWebhookheaderValue:string = ''
}

/**
 * @export 
 * A WebhookheaderResponseCompound Validation Object
 * @class ValidationObjectWebhookheaderResponseCompound
 */
export class ValidationObjectWebhookheaderResponseCompound {
   pkiWebhookheaderID = {
      type: 'integer',
      required: true
   }
   fkiWebhookID = {
      type: 'integer',
      required: true
   }
   sWebhookheaderName = {
      type: 'string',
      pattern: /^(?!(?:e|E)(?:z|Z)(?:m|M)(?:a|A)(?:x|X))(?!(?:h|H)(?:o|O)(?:s|S)(?:t|T)$|(?:u|U)(?:s|S)(?:e|E)(?:r|R)-(?:a|A)(?:g|G)(?:e|E)(?:n|N)(?:t|T)$)(?!\s)[^\s].*$/,
      required: true
   }
   sWebhookheaderValue = {
      type: 'string',
      pattern: /^.{1,255}$/,
      required: true
   }
} 


