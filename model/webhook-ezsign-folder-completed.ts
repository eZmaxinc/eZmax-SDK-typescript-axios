/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { AttemptResponseCompound } from './attempt-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommonWebhook } from './common-webhook';
// May contain unused imports in some cases
// @ts-ignore
import { CustomWebhookResponse } from './custom-webhook-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderResponse } from './ezsignfolder-response';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookEzsignFolderCompletedAllOf } from './webhook-ezsign-folder-completed-all-of';

/**
 * @type WebhookEzsignFolderCompleted
 * This is the base Webhook object
 * @export
 */
export type WebhookEzsignFolderCompleted = CommonWebhook & WebhookEzsignFolderCompletedAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderResponse } from './'
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderResponse } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'

/**
 * @export 
 * A WebhookEzsignFolderCompleted Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEzsignFolderCompleted
 */
export class DataObjectWebhookEzsignFolderCompleted {
   objEzsignfolder:EzsignfolderResponse = new DataObjectEzsignfolderResponse()
   objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
   a_objAttempt:Array<AttemptResponseCompound> = []
}

/**
 * @export 
 * A WebhookEzsignFolderCompleted Validation Object
 * @class ValidationObjectWebhookEzsignFolderCompleted
 */
export class ValidationObjectWebhookEzsignFolderCompleted {
   objEzsignfolder = new ValidationObjectEzsignfolderResponse()
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
} 


