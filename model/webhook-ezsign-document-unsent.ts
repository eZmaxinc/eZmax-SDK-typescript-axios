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

/**
 * @type WebhookEzsignDocumentUnsent
 * This is the base Webhook object
 * @export
 */
/** export type WebhookEzsignDocumentUnsent = CommonWebhook; */
export interface WebhookEzsignDocumentUnsent {
    /**
     * 
     * @type {CustomWebhookResponse}
     * @memberof WebhookEzsignDocumentUnsent
     */
    objWebhook:CustomWebhookResponse 
    /**
     * An array containing details of previous attempts that were made to deliver the message. The array is empty if it\'s the first attempt.
     * @type {Array<AttemptResponseCompound>}
     * @memberof WebhookEzsignDocumentUnsent
     */
    a_objAttempt:Array<AttemptResponseCompound> 
    /**
     * 
     * @type {EzsigndocumentResponse}
     * @memberof WebhookEzsignDocumentUnsent
     */
    objEzsigndocument:EzsigndocumentResponse 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { DataObjectEzsigndocumentResponse } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentResponse } from './'

/**
 * @export 
 * A WebhookEzsignDocumentUnsent Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEzsignDocumentUnsent
 */
export class DataObjectWebhookEzsignDocumentUnsent {
    objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
    a_objAttempt:Array<AttemptResponseCompound> = []
    objEzsigndocument:EzsigndocumentResponse = new DataObjectEzsigndocumentResponse()
}

/**
 * @export 
 * A WebhookEzsignDocumentUnsent Validation Object
 * @class ValidationObjectWebhookEzsignDocumentUnsent
 */
export class ValidationObjectWebhookEzsignDocumentUnsent {
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
   objEzsigndocument = new ValidationObjectEzsigndocumentResponse()
} 


