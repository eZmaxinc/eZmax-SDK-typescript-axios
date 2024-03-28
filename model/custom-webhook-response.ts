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
import { CommonAudit } from './common-audit';
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
// May contain unused imports in some cases
// @ts-ignore
import { WebhookheaderResponseCompound } from './webhookheader-response-compound';

/**
 * @type CustomWebhookResponse
 * A custom Webhook object
 * @export
 */
/** export type CustomWebhookResponse = WebhookResponseCompound; */
export interface CustomWebhookResponse {
    /**
     * The unique ID of the Webhook
     * @type {number}
     * @memberof CustomWebhookResponse
     */
    pkiWebhookID:number 
    /**
     * The description of the Webhook
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookDescription:string 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof CustomWebhookResponse
     */
    fkiEzsignfoldertypeID?:number 
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sEzsignfoldertypeNameX?:string 
    /**
     * 
     * @type {FieldEWebhookModule}
     * @memberof CustomWebhookResponse
     */
    eWebhookModule:FieldEWebhookModule 
    /**
     * 
     * @type {FieldEWebhookEzsignevent}
     * @memberof CustomWebhookResponse
     */
    eWebhookEzsignevent?:FieldEWebhookEzsignevent 
    /**
     * 
     * @type {FieldEWebhookManagementevent}
     * @memberof CustomWebhookResponse
     */
    eWebhookManagementevent?:FieldEWebhookManagementevent 
    /**
     * The URL of the Webhook callback
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookUrl:string 
    /**
     * The email that will receive the Webhook in case all attempts fail
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookEmailfailed:string 
    /**
     * The Apikey for the Webhook.  This will be hidden if we are not creating or regenerating the Apikey.
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookApikey?:string 
    /**
     * The Secret for the Webhook.  This will be hidden if we are not creating or regenerating the Apikey.
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookSecret?:string 
    /**
     * Whether the Webhook is active or not
     * @type {boolean}
     * @memberof CustomWebhookResponse
     */
    bWebhookIsactive:boolean 
    /**
     * Whether the requests will be signed or not
     * @type {boolean}
     * @memberof CustomWebhookResponse
     */
    bWebhookIssigned:boolean 
    /**
     * Wheter the server\'s SSL certificate should be validated or not. Not recommended to skip for production use
     * @type {boolean}
     * @memberof CustomWebhookResponse
     */
    bWebhookSkipsslvalidation:boolean 
    /**
     * 
     * @type {CommonAudit}
     * @memberof CustomWebhookResponse
     */
    objAudit:CommonAudit 
    /**
     * The concatenated string to describe the Webhook event
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    sWebhookEvent?:string 
    /**
     * 
     * @type {Array<WebhookheaderResponseCompound>}
     * @memberof CustomWebhookResponse
     */
    a_objWebhookheader?:Array<WebhookheaderResponseCompound> 
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof CustomWebhookResponse
     */
    pksCustomerCode:string 
    /**
     * Wheter the webhook received is a manual test or a real event
     * @type {boolean}
     * @memberof CustomWebhookResponse
     */
    bWebhookTest:boolean 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A CustomWebhookResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomWebhookResponse
 */
export class DataObjectCustomWebhookResponse {
    pkiWebhookID:number = 0
    sWebhookDescription:string = ''
    fkiEzsignfoldertypeID?:number = undefined
    sEzsignfoldertypeNameX?:string = undefined
    eWebhookModule:FieldEWebhookModule = 'Ezsign'
    eWebhookEzsignevent?:FieldEWebhookEzsignevent = undefined
    eWebhookManagementevent?:FieldEWebhookManagementevent = undefined
    sWebhookUrl:string = ''
    sWebhookEmailfailed:string = ''
    sWebhookApikey?:string = undefined
    sWebhookSecret?:string = undefined
    bWebhookIsactive:boolean = false
    bWebhookIssigned:boolean = false
    bWebhookSkipsslvalidation:boolean = false
    objAudit:CommonAudit = new DataObjectCommonAudit()
    sWebhookEvent?:string = undefined
    a_objWebhookheader?:Array<WebhookheaderResponseCompound> = undefined
    pksCustomerCode:string = ''
    bWebhookTest:boolean = false
}

/**
 * @export 
 * A CustomWebhookResponse Validation Object
 * @class ValidationObjectCustomWebhookResponse
 */
export class ValidationObjectCustomWebhookResponse {
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
      maximum: 65535,
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
      required: true
   }
   sWebhookEmailfailed = {
      type: 'string',
      required: true
   }
   sWebhookApikey = {
      type: 'string',
      required: false
   }
   sWebhookSecret = {
      type: 'string',
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
   bWebhookSkipsslvalidation = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
   sWebhookEvent = {
      type: 'string',
      required: false
   }
   a_objWebhookheader = {
      type: 'array',
      required: false
   }
   pksCustomerCode = {
      type: 'string',
      required: true
   }
   bWebhookTest = {
      type: 'boolean',
      required: true
   }
} 


