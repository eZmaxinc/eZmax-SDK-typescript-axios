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
import { FieldEWebhookEzsignevent } from './field-ewebhook-ezsignevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookManagementevent } from './field-ewebhook-managementevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookModule } from './field-ewebhook-module';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookRequest } from './webhook-request';

/**
 * @type WebhookRequestCompound
 * A Webhook Object and children
 * @export
 */
export type WebhookRequestCompound = WebhookRequest;



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookRequestCompound
 */
export class DataObjectWebhookRequestCompound {
   pkiWebhookID?:number = undefined
   fkiEzsignfoldertypeID?:number = undefined
   sWebhookDescription:string = ''
   eWebhookModule:FieldEWebhookModule = 'Ezsign'
   eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
   eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
   sWebhookUrl:string = ''
   sWebhookEmailfailed:string = ''
   bWebhookIsactive:boolean = false
   bWebhookSkipsslvalidation:boolean = false
}

/**
 * @export 
 * A WebhookRequestCompound Validation Object
 * @class ValidationObjectWebhookRequestCompound
 */
export class ValidationObjectWebhookRequestCompound {
   pkiWebhookID = {
      type: 'integer',
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sWebhookDescription = {
      type: 'string',
      required: true
   }
   eWebhookModule = {
      type: 'enum',
      allowableValues: ['Ezsign','Management'],
      required: true
   }
   eWebhookEzsignevent = {
      type: 'enum',
      allowableValues: ['DocumentCompleted','FolderCompleted'],
      required: false
   }
   eWebhookManagementevent = {
      type: 'enum',
      allowableValues: ['UserCreated'],
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
      required: true
   }
   bWebhookSkipsslvalidation = {
      type: 'boolean',
      required: true
   }
} 


