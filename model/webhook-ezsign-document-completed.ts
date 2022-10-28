/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
import { EzsigndocumentResponse } from './ezsigndocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookEzsignDocumentCompletedAllOf } from './webhook-ezsign-document-completed-all-of';

import { DefaultObject } from '../base'

/**
 * @type WebhookEzsignDocumentCompleted
 * This is the base Webhook object
 * @export
 */
export type WebhookEzsignDocumentCompleted = CommonWebhook & WebhookEzsignDocumentCompletedAllOf;


/**
 * @export 
 * A WebhookEzsignDocumentCompleted Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookEzsignDocumentCompleted
 */
export class DefaultObjectWebhookEzsignDocumentCompleted extends DefaultObject {
   objEzsigndocument:Partial<EzsigndocumentResponse> = {}
   objWebhook:Partial<CustomWebhookResponse> = {}
   a_objAttempt:Array<AttemptResponseCompound> = []
}


