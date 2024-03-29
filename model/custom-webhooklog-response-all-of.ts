/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * 
 * @export
 * @interface CustomWebhooklogResponseAllOf
 */
export interface CustomWebhooklogResponseAllOf {
    /**
     * The date and time at which the Webhooklog happened.
     * @type {string}
     * @memberof CustomWebhooklogResponseAllOf
     */
    'dtWebhooklogDate': string;
    /**
     * The Json containing the Webhook call and return
     * @type {string}
     * @memberof CustomWebhooklogResponseAllOf
     */
    'tWebhooklogJson': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomWebhooklogResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomWebhooklogResponseAllOf
 */
export class DataObjectCustomWebhooklogResponseAllOf {
   dtWebhooklogDate:string = ''
   tWebhooklogJson:string = ''
}

/**
 * @export 
 * A CustomWebhooklogResponseAllOf Validation Object
 * @class ValidationObjectCustomWebhooklogResponseAllOf
 */
export class ValidationObjectCustomWebhooklogResponseAllOf {
   dtWebhooklogDate = {
      type: 'string',
      required: true
   }
   tWebhooklogJson = {
      type: 'string',
      required: true
   }
} 


