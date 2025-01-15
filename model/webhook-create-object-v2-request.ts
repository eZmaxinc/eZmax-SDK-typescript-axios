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


// May contain unused imports in some cases
// @ts-ignore
import type { WebhookRequestCompound } from './webhook-request-compound';

/**
 * Request for POST /2/object/webhook
 * @export
 * @interface WebhookCreateObjectV2Request
 */
export interface WebhookCreateObjectV2Request {
    /**
     * 
     * @type {Array<WebhookRequestCompound>}
     * @memberof WebhookCreateObjectV2Request
     */
    /*'a_objWebhook': Array<WebhookRequestCompound>;*/
    'a_objWebhook': Array<WebhookRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookCreateObjectV2Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookCreateObjectV2Request
 */
export class DataObjectWebhookCreateObjectV2Request {
   a_objWebhook:Array<WebhookRequestCompound> = []
}

/**
 * @export 
 * A WebhookCreateObjectV2Request Validation Object
 * @class ValidationObjectWebhookCreateObjectV2Request
 */
export class ValidationObjectWebhookCreateObjectV2Request {
   a_objWebhook = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


