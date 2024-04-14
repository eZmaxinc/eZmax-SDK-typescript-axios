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
import { FieldEWebhookEzsignevent } from './field-ewebhook-ezsignevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookManagementevent } from './field-ewebhook-managementevent';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEWebhookModule } from './field-ewebhook-module';

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
    /*'pkiWebhookID'?: number;*/
    'pkiWebhookID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof WebhookRequest
     */
    /*'fkiEzsignfoldertypeID'?: number;*/
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof WebhookRequest
     */
    /*'sWebhookDescription': string;*/
    'sWebhookDescription': string;
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof WebhookRequest
     */
    /*'eWebhookModule': FieldEWebhookModule;*/
    'eWebhookModule': FieldEWebhookModule;
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof WebhookRequest
     */
    /*'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;*/
    'eWebhookEzsignevent'?: FieldEWebhookEzsignevent;
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof WebhookRequest
     */
    /*'eWebhookManagementevent'?: FieldEWebhookManagementevent;*/
    'eWebhookManagementevent'?: FieldEWebhookManagementevent;
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof WebhookRequest
     */
    /*'sWebhookUrl': string;*/
    'sWebhookUrl': string;
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof WebhookRequest
     */
    /*'sWebhookEmailfailed': string;*/
    'sWebhookEmailfailed': string;
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof WebhookRequest
     */
    /*'bWebhookIsactive': boolean;*/
    'bWebhookIsactive': boolean;
    /**
     * Whether the requests will be signed or not
     * @type {boolean}
     * @memberof WebhookRequest
     */
    /*'bWebhookIssigned'?: boolean;*/
    'bWebhookIssigned'?: boolean;
    /**
     * Wheter the server\'s SSL certificate should be validated or not. Not recommended to skip for production use
     * @type {boolean}
     * @memberof WebhookRequest
     */
    /*'bWebhookSkipsslvalidation': boolean;*/
    'bWebhookSkipsslvalidation': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookRequest
 */
export class DataObjectWebhookRequest {
   pkiWebhookID?:number = undefined
   fkiEzsignfoldertypeID?:number = undefined
   sWebhookDescription:string = ''
   eWebhookModule:FieldEWebhookModule = 'Ezsign'
   eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
   eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
   sWebhookUrl:string = ''
   sWebhookEmailfailed:string = ''
   bWebhookIsactive:boolean = false
   bWebhookIssigned?:boolean = undefined
   bWebhookSkipsslvalidation:boolean = false
}

/**
 * @export 
 * A WebhookRequest Validation Object
 * @class ValidationObjectWebhookRequest
 */
export class ValidationObjectWebhookRequest {
   pkiWebhookID = {
      type: 'integer',
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
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
      allowableValues: ['DocumentCompleted','DocumentFormCompleted','DocumentUnsent','EzsignsignerAcceptclause','EzsignsignerConnect','FolderCompleted','FolderDisposed','FolderSent','FolderUnsent','SignatureSigned'],
      required: false
   }
   eWebhookManagementevent = {
      type: 'enum',
      allowableValues: ['UserCreated','UserstagedCreated'],
      required: false
   }
   sWebhookUrl = {
      type: 'string',
      pattern: '/^(https|http):\\/\\/[^\s\\/$.?#].[^\s]*$/',
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
   bWebhookIssigned = {
      type: 'boolean',
      required: false
   }
   bWebhookSkipsslvalidation = {
      type: 'boolean',
      required: true
   }
} 


