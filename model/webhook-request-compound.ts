/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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

import { DefaultObject } from '../base'

/**
 * @type WebhookRequestCompound
 * A Webhook Object and children
 * @export
 */
export type WebhookRequestCompound = WebhookRequest;


/**
 * @export 
 * A WebhookRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookRequestCompound
 */
export class DefaultObjectWebhookRequestCompound extends DefaultObject {
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

