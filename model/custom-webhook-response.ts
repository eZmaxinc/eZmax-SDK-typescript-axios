/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomWebhookResponseAllOf } from './custom-webhook-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookEzsignevent } from './field-ewebhook-ezsignevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookManagementevent } from './field-ewebhook-managementevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookModule } from './field-ewebhook-module';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookResponse } from './webhook-response';

/**
 * @type CustomWebhookResponse
 * A custom Webhook object
 * @export
 */
export type CustomWebhookResponse = CustomWebhookResponseAllOf & WebhookResponse;



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomWebhookResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomWebhookResponse
 */
export class DataObjectCustomWebhookResponse {
    pksCustomerCode:string = ''
    bWebhookTest:boolean = false
    pkiWebhookID:number = 0
    sWebhookDescription:string = ''
    fkiEzsignfoldertypeID?:number = undefined
    sEzsignfoldertypeNameX?:string = undefined
    eWebhookModule:FieldEWebhookModule = 'Ezsign'
    eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
    eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
    sWebhookUrl:string = ''
    sWebhookEmailfailed:string = ''
    bWebhookIsactive?:boolean = undefined
    bWebhookSkipsslvalidation:boolean = false
}

/**
 * @export 
 * A CustomWebhookResponse Validation Object
 * @class ValidationObjectCustomWebhookResponse
 */
export class ValidationObjectCustomWebhookResponse {
   pksCustomerCode = {
      type: 'string',
      required: true
   }
   bWebhookTest = {
      type: 'boolean',
      required: true
   }
   pkiWebhookID = {
      type: 'integer',
      required: true
   }
   sWebhookDescription = {
      type: 'string',
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   eWebhookModule = {
      type: 'enum',
      allowableValues: ['Ezsign','Management'],
      required: true
   }
   eWebhookEzsignevent = {
      type: 'enum',
      allowableValues: ['DocumentCompleted','EzsignsignerAcceptclause','EzsignsignerConnect','FolderCompleted'],
      required: false
   }
   eWebhookManagementevent = {
      type: 'enum',
      allowableValues: ['UserCreated','UserstagedCreated'],
      required: false
   }
   sWebhookUrl = {
      type: 'string',
      required: true
   }
   sWebhookEmailfailed = {
      type: 'string',
      required: true
   }
   bWebhookIsactive = {
      type: 'boolean',
      required: false
   }
   bWebhookSkipsslvalidation = {
      type: 'boolean',
      required: true
   }
} 


