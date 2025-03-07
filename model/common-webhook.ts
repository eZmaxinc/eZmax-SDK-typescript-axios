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
import type { AttemptResponseCompound } from './attempt-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomWebhookResponse } from './custom-webhook-response';

/**
 * This is the base Webhook object
 * @export
 * @interface CommonWebhook
 */
export interface CommonWebhook {
    /**
     * 
     * @type {CustomWebhookResponse}
     * @memberof CommonWebhook
     */
    /*'objWebhook': CustomWebhookResponse;*/
    'objWebhook': CustomWebhookResponse;
    /**
     * An array containing details of previous attempts that were made to deliver the message. The array is empty if it\'s the first attempt.
     * @type {Array<AttemptResponseCompound>}
     * @memberof CommonWebhook
     */
    /*'a_objAttempt': Array<AttemptResponseCompound>;*/
    'a_objAttempt': Array<AttemptResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'

/**
 * @export 
 * A CommonWebhook Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonWebhook
 */
export class DataObjectCommonWebhook {
   objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
   a_objAttempt:Array<AttemptResponseCompound> = []
}

/**
 * @export 
 * A CommonWebhook Validation Object
 * @class ValidationObjectCommonWebhook
 */
export class ValidationObjectCommonWebhook {
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
} 


