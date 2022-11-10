/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
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
 * A Webhook List Element
 * @export
 * @interface WebhookListElement
 */
export interface WebhookListElement {
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof WebhookListElement
     */
    'pkiWebhookID': number;
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof WebhookListElement
     */
    'sWebhookDescription': string;
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof WebhookListElement
     */
    'sWebhookUrl': string;
    /**
     * The concatenated string to describe the Webhook event
     * @type {string}
     * @memberof WebhookListElement
     */
    'sWebhookEvent': string;
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof WebhookListElement
     */
    'sWebhookEmailfailed': string;
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof WebhookListElement
     */
    'eWebhookModule': FieldEWebhookModule;
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof WebhookListElement
     */
    'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof WebhookListElement
     */
    'eWebhookManagementevent'?: FieldEWebhookManagementevent;
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof WebhookListElement
     */
    'bWebhookIsactive': boolean;
}
/**
 * A WebhookListElement Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookListElement
 */
export class DefaultObjectWebhookListElement extends DefaultObject {
   pkiWebhookID:number = 0
   sWebhookDescription:string = ''
   sWebhookUrl:string = ''
   sWebhookEvent:string = ''
   sWebhookEmailfailed:string = ''
   eWebhookModule:FieldEWebhookModule = 'Ezsign'
   eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
   eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
   bWebhookIsactive:boolean = false
}


