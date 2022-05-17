/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { AttemptResponseCompound } from './attempt-response-compound';
import { WebhookResponse } from './webhook-response';

/**
 * This is the base Webhook object
 * @export
 * @interface CommonWebhook
 */
export interface CommonWebhook {
    /**
     * 
     * @type {WebhookResponse}
     * @memberof CommonWebhook
     */
    'objWebhook': WebhookResponse;
    /**
     * An array containing details of previous attempts that were made to deliver the message. The array is empty if it\'s the first attempt.
     * @type {Array<AttemptResponseCompound>}
     * @memberof CommonWebhook
     */
    'a_objAttempt': Array<AttemptResponseCompound>;
}

