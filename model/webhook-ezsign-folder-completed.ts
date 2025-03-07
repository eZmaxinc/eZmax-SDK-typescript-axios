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
import type { CommonWebhook } from './common-webhook';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomWebhookResponse } from './custom-webhook-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfolderResponse } from './ezsignfolder-response';

/**
 * @type WebhookEzsignFolderCompleted
 * This is the base Webhook object
 * @export
 */
/*export type WebhookEzsignFolderCompleted = CommonWebhook;*/
export interface WebhookEzsignFolderCompleted {
    /**
     * 
     * @type {CustomWebhookResponse}
     * @memberof WebhookEzsignFolderCompleted
     */
    objWebhook:CustomWebhookResponse 
    /**
     * An array containing details of previous attempts that were made to deliver the message. The array is empty if it\'s the first attempt.
     * @type {Array<AttemptResponseCompound>}
     * @memberof WebhookEzsignFolderCompleted
     */
    a_objAttempt:Array<AttemptResponseCompound> 
    /**
     * 
     * @type {EzsignfolderResponse}
     * @memberof WebhookEzsignFolderCompleted
     */
    objEzsignfolder:EzsignfolderResponse 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { DataObjectEzsignfolderResponse } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderResponse } from './'

/**
 * @export 
 * A WebhookEzsignFolderCompleted Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEzsignFolderCompleted
 */
export class DataObjectWebhookEzsignFolderCompleted {
    objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
    a_objAttempt:Array<AttemptResponseCompound> = []
    objEzsignfolder:EzsignfolderResponse = new DataObjectEzsignfolderResponse()
}

/**
 * @export 
 * A WebhookEzsignFolderCompleted Validation Object
 * @class ValidationObjectWebhookEzsignFolderCompleted
 */
export class ValidationObjectWebhookEzsignFolderCompleted {
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
   objEzsignfolder = new ValidationObjectEzsignfolderResponse()
} 


