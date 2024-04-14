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
import { WebhookRequestCompound } from './webhook-request-compound';

/**
 * Request for PUT /1/object/webhook/{pkiWebhookID}
 * @export
 * @interface WebhookEditObjectV1Request
 */
export interface WebhookEditObjectV1Request {
    /**
     * 
     * @type {WebhookRequestCompound}
     * @memberof WebhookEditObjectV1Request
     */
    /*'objWebhook': WebhookRequestCompound;*/
    'objWebhook': WebhookRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookRequestCompound } from './'
// @ts-ignore
import { ValidationObjectWebhookRequestCompound } from './'

/**
 * @export 
 * A WebhookEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEditObjectV1Request
 */
export class DataObjectWebhookEditObjectV1Request {
   objWebhook:WebhookRequestCompound = new DataObjectWebhookRequestCompound()
}

/**
 * @export 
 * A WebhookEditObjectV1Request Validation Object
 * @class ValidationObjectWebhookEditObjectV1Request
 */
export class ValidationObjectWebhookEditObjectV1Request {
   objWebhook = new ValidationObjectWebhookRequestCompound()
} 


