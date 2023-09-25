/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookListElement } from './webhook-list-element';

/**
 * @type WebhookGetListV1ResponseMPayload
 * Payload for GET /1/object/webhook/getList
 * @export
 */
/** export type WebhookGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload; */
export interface WebhookGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof WebhookGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof WebhookGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<WebhookListElement>}
     * @memberof WebhookGetListV1ResponseMPayload
     */
    a_objWebhook:Array<WebhookListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetListV1ResponseMPayload
 */
export class DataObjectWebhookGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objWebhook:Array<WebhookListElement> = []
}

/**
 * @export 
 * A WebhookGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectWebhookGetListV1ResponseMPayload
 */
export class ValidationObjectWebhookGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objWebhook = {
      type: 'array',
      required: true
   }
} 


