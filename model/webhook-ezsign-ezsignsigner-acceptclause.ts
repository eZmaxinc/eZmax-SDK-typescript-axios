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
import { EzsignfoldersignerassociationResponseCompound } from './ezsignfoldersignerassociation-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookEzsignEzsignsignerAcceptclauseAllOf } from './webhook-ezsign-ezsignsigner-acceptclause-all-of';

/**
 * @type WebhookEzsignEzsignsignerAcceptclause
 * This is the base Webhook object
 * @export
 */
export type WebhookEzsignEzsignsignerAcceptclause = CommonWebhook & WebhookEzsignEzsignsignerAcceptclauseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderResponse } from './'
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationResponseCompound } from './'
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'

/**
 * @export 
 * A WebhookEzsignEzsignsignerAcceptclause Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEzsignEzsignsignerAcceptclause
 */
export class DataObjectWebhookEzsignEzsignsignerAcceptclause {
   objEzsignfolder?:EzsignfolderResponse = undefined
   objEzsignfoldersignerassociation:EzsignfoldersignerassociationResponseCompound = new DataObjectEzsignfoldersignerassociationResponseCompound()
   objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
   a_objAttempt:Array<AttemptResponseCompound> = []
}

/**
 * @export 
 * A WebhookEzsignEzsignsignerAcceptclause Validation Object
 * @class ValidationObjectWebhookEzsignEzsignsignerAcceptclause
 */
export class ValidationObjectWebhookEzsignEzsignsignerAcceptclause {
   objEzsignfolder = new ValidationObjectEzsignfolderResponse()
   objEzsignfoldersignerassociation = new ValidationObjectEzsignfoldersignerassociationResponseCompound()
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
} 


