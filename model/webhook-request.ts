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
 * A Webhook Object
 * @export
 * @interface WebhookRequest
 */
export interface WebhookRequest {
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof WebhookRequest
     */
    'pkiWebhookID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof WebhookRequest
     */
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof WebhookRequest
     */
    'sWebhookDescription': string;
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof WebhookRequest
     */
    'eWebhookModule': FieldEWebhookModule;
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof WebhookRequest
     */
    'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof WebhookRequest
     */
    'eWebhookManagementevent'?: FieldEWebhookManagementevent;
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof WebhookRequest
     */
    'sWebhookUrl': string;
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof WebhookRequest
     */
    'sWebhookEmailfailed': string;
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof WebhookRequest
     */
    'bWebhookIsactive': boolean;
    /**
     * Wheter the server\'s SSL certificate should be validated or not. Not recommended to skip for production use
     * @type {boolean}
     * @memberof WebhookRequest
     */
    'bWebhookSkipsslvalidation': boolean;
}
/**
 * A WebhookRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookRequest
 */
export class DefaultObjectWebhookRequest extends DefaultObject {
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

