/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { AttemptResponseCompound } from './attempt-response-compound';
import { CommonWebhook } from './common-webhook';
import { EzsigndocumentResponse } from './ezsigndocument-response';
import { WebhookEzsignDocumentCompletedAllOf } from './webhook-ezsign-document-completed-all-of';
import { WebhookResponse } from './webhook-response';

/**
 * @type WebhookEzsignDocumentCompleted
 * This is the base Webhook object
 * @export
 */
export type WebhookEzsignDocumentCompleted = CommonWebhook & WebhookEzsignDocumentCompletedAllOf;


