/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.1
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
 * @type WebhookEzsignFolderCompleted
 * This is the base Webhook object
 * @export
 */
export type WebhookEzsignFolderCompleted = CommonWebhook & WebhookEzsignFolderCompletedAllOf;


