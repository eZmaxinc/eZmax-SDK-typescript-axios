/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FieldEWebhookEzsignevent } from './field-ewebhook-ezsignevent';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEWebhookManagementevent } from './field-ewebhook-managementevent';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEWebhookModule } from './field-ewebhook-module';

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
    /*'pkiWebhookID': number;*/
    'pkiWebhookID': number;
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof WebhookListElement
     */
    /*'sWebhookDescription': string;*/
    'sWebhookDescription': string;
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof WebhookListElement
     */
    /*'sWebhookUrl': string;*/
    'sWebhookUrl': string;
    /**
     * The concatenated string to describe the Webhook event
     * @type {string}
     * @memberof WebhookListElement
     */
    /*'sWebhookEvent': string;*/
    'sWebhookEvent': string;
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof WebhookListElement
     */
    /*'sWebhookEmailfailed': string;*/
    'sWebhookEmailfailed': string;
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof WebhookListElement
     */
    /*'eWebhookModule': FieldEWebhookModule;*/
    'eWebhookModule': FieldEWebhookModule;
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof WebhookListElement
     */
    /*'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;*/
    'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof WebhookListElement
     */
    /*'eWebhookManagementevent'?: FieldEWebhookManagementevent;*/
    'eWebhookManagementevent'?: FieldEWebhookManagementevent;
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof WebhookListElement
     */
    /*'bWebhookIsactive': boolean;*/
    'bWebhookIsactive': boolean;
    /**
     * Whether the requests will be signed or not
     * @type {boolean}
     * @memberof WebhookListElement
     */
    /*'bWebhookIssigned': boolean;*/
    'bWebhookIssigned': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookListElement
 */
export class DataObjectWebhookListElement {
   pkiWebhookID:number = 0
   sWebhookDescription:string = ''
   sWebhookUrl:string = ''
   sWebhookEvent:string = ''
   sWebhookEmailfailed:string = ''
   eWebhookModule:FieldEWebhookModule = 'Ezsign'
   eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
   eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
   bWebhookIsactive:boolean = false
   bWebhookIssigned:boolean = false
}

/**
 * @export 
 * A WebhookListElement Validation Object
 * @class ValidationObjectWebhookListElement
 */
export class ValidationObjectWebhookListElement {
   pkiWebhookID = {
      type: 'integer',
      required: true
   }
   sWebhookDescription = {
      type: 'string',
      required: true
   }
   sWebhookUrl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: true
   }
   sWebhookEvent = {
      type: 'string',
      required: true
   }
   sWebhookEmailfailed = {
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
      allowableValues: ['DocumentCompleted','DocumentFormCompleted','DocumentUnsent','EzsignsignerAcceptclause','EzsignsignerConnect','FolderCompleted','FolderDisposed','FolderSent','FolderUnsent','SignatureSigned'],
      required: false
   }
   eWebhookManagementevent = {
      type: 'enum',
      allowableValues: ['UserCreated','UserstagedCreated'],
      required: false
   }
   bWebhookIsactive = {
      type: 'boolean',
      required: true
   }
   bWebhookIssigned = {
      type: 'boolean',
      required: true
   }
} 


