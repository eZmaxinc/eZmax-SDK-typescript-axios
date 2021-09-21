/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { AttemptResponse } from './attempt-response';
import { CommonWebhook } from './common-webhook';
import { EzsignfolderResponse } from './ezsignfolder-response';
import { WebhookEzsignFolderCompletedAllOf } from './webhook-ezsign-folder-completed-all-of';
import { WebhookResponse } from './webhook-response';



/**
 * This is the base Webhook object
 * @export
 * @interface WebhookEzsignFolderCompleted
 */
export interface WebhookEzsignFolderCompleted {
    /**
     * 
     * @type {EzsignfolderResponse}
     * @memberof WebhookEzsignFolderCompleted
     */
    objEzsignfolder: EzsignfolderResponse;
    /**
     * 
     * @type {WebhookResponse}
     * @memberof WebhookEzsignFolderCompleted
     */
    objWebhook: WebhookResponse;
    /**
     * An array containing details of previous attempts that were made to deliver the message. The array is empty if it\'s the first attempt.
     * @type {Array<AttemptResponse>}
     * @memberof WebhookEzsignFolderCompleted
     */
    a_objAttempt: Array<AttemptResponse>;
}
