/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A webhookheader object
 * @export
 * @interface WebhookheaderResponse
 */
export interface WebhookheaderResponse {
    /**
     * The unique ID of the Webhookheader
     * @type {number}
     * @memberof WebhookheaderResponse
     */
    /*'pkiWebhookheaderID': number;*/
    'pkiWebhookheaderID': number;
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof WebhookheaderResponse
     */
    /*'fkiWebhookID': number;*/
    'fkiWebhookID': number;
    /**
     * The Name of the Webhookheader
     * @type {string}
     * @memberof WebhookheaderResponse
     */
    /*'sWebhookheaderName': string;*/
    'sWebhookheaderName': string;
    /**
     * The Value of the Webhookheader
     * @type {string}
     * @memberof WebhookheaderResponse
     */
    /*'sWebhookheaderValue': string;*/
    'sWebhookheaderValue': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookheaderResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookheaderResponse
 */
export class DataObjectWebhookheaderResponse {
   pkiWebhookheaderID:number = 0
   fkiWebhookID:number = 0
   sWebhookheaderName:string = ''
   sWebhookheaderValue:string = ''
}

/**
 * @export 
 * A WebhookheaderResponse Validation Object
 * @class ValidationObjectWebhookheaderResponse
 */
export class ValidationObjectWebhookheaderResponse {
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
      pattern: '/^(?!(?:e|E)(?:z|Z)(?:m|M)(?:a|A)(?:x|X))(?!(?:h|H)(?:o|O)(?:s|S)(?:t|T)$|(?:u|U)(?:s|S)(?:e|E)(?:r|R)-(?:a|A)(?:g|G)(?:e|E)(?:n|N)(?:t|T)$)(?!\s)[^\s].*$/',
      required: true
   }
   sWebhookheaderValue = {
      type: 'string',
      pattern: '/^.{1,255}$/',
      required: true
   }
} 


