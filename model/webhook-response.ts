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

import { DefaultObject } from '../base'

/**
 * A webhook object
 * @export
 * @interface WebhookResponse
 */
export interface WebhookResponse {
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof WebhookResponse
     */
    'pkiWebhookID': number;
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof WebhookResponse
     */
    'sWebhookDescription': string;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof WebhookResponse
     */
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof WebhookResponse
     */
    'sEzsignfoldertypeNameX'?: string;
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof WebhookResponse
     */
    'eWebhookModule': FieldEWebhookModule;
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof WebhookResponse
     */
    'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof WebhookResponse
     */
    'eWebhookManagementevent'?: FieldEWebhookManagementevent;
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof WebhookResponse
     */
    'sWebhookUrl': string;
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof WebhookResponse
     */
    'sWebhookEmailfailed': string;
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof WebhookResponse
     */
    'bWebhookIsactive'?: boolean;
    /**
     * Wheter the server\'s SSL certificate should be validated or not. Not recommended to skip for production use
     * @type {boolean}
     * @memberof WebhookResponse
     */
    'bWebhookSkipsslvalidation': boolean;
}
/**
 * A WebhookResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookResponse
 */
export class DefaultObjectWebhookResponse extends DefaultObject {
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


