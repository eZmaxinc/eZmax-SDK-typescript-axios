/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { WebhookResponseCompound } from './webhook-response-compound';

import { DefaultObject } from '../base'

/**
 * @type WebhookGetObjectV1ResponseMPayload
 * Payload for GET /1/object/webhook/{pkiWebhookID}
 * @export
 */
export type WebhookGetObjectV1ResponseMPayload = WebhookResponseCompound;


/**
 * @export 
 * A WebhookGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookGetObjectV1ResponseMPayload
 */
export class DefaultObjectWebhookGetObjectV1ResponseMPayload extends DefaultObject {
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
   sWebhookEvent:string = ''
}


