/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
import { FieldEEzsigndocumentStep } from './field-eezsigndocument-step';

/**
 * An Ezsigndocument Object
 * @export
 * @interface EzsigndocumentResponse
 */
export interface EzsigndocumentResponse {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'pkiEzsigndocumentID': number;*/
    'pkiEzsigndocumentID': number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'fkiEzsignfolderID': number;*/
    'fkiEzsignfolderID': number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'fkiEzsignfoldersignerassociationIDDeclinedtosign'?: number;*/
    'fkiEzsignfoldersignerassociationIDDeclinedtosign'?: number;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'dtEzsigndocumentDuedate': string;*/
    'dtEzsigndocumentDuedate': string;
    /**
     * The date and time at which the Ezsignform has been completed.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'dtEzsignformCompleted'?: string;*/
    'dtEzsignformCompleted'?: string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'fkiLanguageID'?: number;*/
    'fkiLanguageID'?: number;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'sEzsigndocumentName': string;*/
    'sEzsigndocumentName': string;
    /**
     * 
     * @type {FieldEEzsigndocumentStep}
     * @memberof EzsigndocumentResponse
     */
    /*'eEzsigndocumentStep': FieldEEzsigndocumentStep;*/
    'eEzsigndocumentStep': FieldEEzsigndocumentStep;
    /**
     * The date and time when the Ezsigndocument was first sent.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'dtEzsigndocumentFirstsend'?: string;*/
    'dtEzsigndocumentFirstsend'?: string;
    /**
     * The date and time when the Ezsigndocument was sent the last time.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'dtEzsigndocumentLastsend'?: string;*/
    'dtEzsigndocumentLastsend'?: string;
    /**
     * The order in which the Ezsigndocument will be presented to the signatory in the Ezsignfolder.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentOrder': number;*/
    'iEzsigndocumentOrder': number;
    /**
     * The number of pages in the Ezsigndocument.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentPagetotal': number;*/
    'iEzsigndocumentPagetotal': number;
    /**
     * The number of signatures that were signed in the document.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentSignaturesigned': number;*/
    'iEzsigndocumentSignaturesigned': number;
    /**
     * The number of total signatures that were requested in the Ezsigndocument.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentSignaturetotal': number;*/
    'iEzsigndocumentSignaturetotal': number;
    /**
     * MD5 Hash of the initial PDF Document before signatures were applied to it.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'sEzsigndocumentMD5initial'?: string;*/
    'sEzsigndocumentMD5initial'?: string;
    /**
     * A custom text message that will contain the refusal message if the Ezsigndocument is declined to sign
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'tEzsigndocumentDeclinedtosignreason'?: string;*/
    'tEzsigndocumentDeclinedtosignreason'?: string;
    /**
     * MD5 Hash of the final PDF Document after all signatures were applied to it.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'sEzsigndocumentMD5signed'?: string;*/
    'sEzsigndocumentMD5signed'?: string;
    /**
     * If the Ezsigndocument contains an Ezsignform or not
     * @type {boolean}
     * @memberof EzsigndocumentResponse
     */
    /*'bEzsigndocumentEzsignform'?: boolean;*/
    'bEzsigndocumentEzsignform'?: boolean;
    /**
     * If the Ezsigndocument contains signed signatures (From internal or external sources)
     * @type {boolean}
     * @memberof EzsigndocumentResponse
     */
    /*'bEzsigndocumentHassignedsignatures'?: boolean;*/
    'bEzsigndocumentHassignedsignatures'?: boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsigndocumentResponse
     */
    /*'objAudit'?: CommonAudit;*/
    'objAudit'?: CommonAudit;
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    /*'sEzsigndocumentExternalid'?: string;*/
    'sEzsigndocumentExternalid'?: string;
    /**
     * The number of Ezsigndocumentattachment total
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentEzsignsignatureattachmenttotal': number;*/
    'iEzsigndocumentEzsignsignatureattachmenttotal': number;
    /**
     * The total number of Ezsigndiscussions
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    /*'iEzsigndocumentEzsigndiscussiontotal': number;*/
    'iEzsigndocumentEzsigndiscussiontotal': number;
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
 * A EzsigndocumentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentResponse
 */
export class DataObjectEzsigndocumentResponse {
   pkiEzsigndocumentID:number = 0
   fkiEzsignfolderID:number = 0
   fkiEzsignfoldersignerassociationIDDeclinedtosign?:number = undefined
   dtEzsigndocumentDuedate:string = ''
   dtEzsignformCompleted?:string = undefined
   fkiLanguageID?:number = undefined
   sEzsigndocumentName:string = ''
   eEzsigndocumentStep:FieldEEzsigndocumentStep = 'Unsent'
   dtEzsigndocumentFirstsend?:string = undefined
   dtEzsigndocumentLastsend?:string = undefined
   iEzsigndocumentOrder:number = 0
   iEzsigndocumentPagetotal:number = 0
   iEzsigndocumentSignaturesigned:number = 0
   iEzsigndocumentSignaturetotal:number = 0
   sEzsigndocumentMD5initial?:string = undefined
   tEzsigndocumentDeclinedtosignreason?:string = undefined
   sEzsigndocumentMD5signed?:string = undefined
   bEzsigndocumentEzsignform?:boolean = undefined
   bEzsigndocumentHassignedsignatures?:boolean = undefined
   objAudit?:CommonAudit = undefined
   sEzsigndocumentExternalid?:string = undefined
   iEzsigndocumentEzsignsignatureattachmenttotal:number = 0
   iEzsigndocumentEzsigndiscussiontotal:number = 0
}

/**
 * @export 
 * A EzsigndocumentResponse Validation Object
 * @class ValidationObjectEzsigndocumentResponse
 */
export class ValidationObjectEzsigndocumentResponse {
   pkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldersignerassociationIDDeclinedtosign = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtEzsigndocumentDuedate = {
      type: 'string',
      required: true
   }
   dtEzsignformCompleted = {
      type: 'string',
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: false
   }
   sEzsigndocumentName = {
      type: 'string',
      required: true
   }
   eEzsigndocumentStep = {
      type: 'enum',
      allowableValues: ['Unsent','Unsigned','PartiallySigned','DeclinedToSign','PrematurelyEnded','PendingCompletion','Completed','Disposed'],
      required: true
   }
   dtEzsigndocumentFirstsend = {
      type: 'string',
      required: false
   }
   dtEzsigndocumentLastsend = {
      type: 'string',
      required: false
   }
   iEzsigndocumentOrder = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigndocumentPagetotal = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigndocumentSignaturesigned = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigndocumentSignaturetotal = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigndocumentMD5initial = {
      type: 'string',
      required: false
   }
   tEzsigndocumentDeclinedtosignreason = {
      type: 'string',
      required: false
   }
   sEzsigndocumentMD5signed = {
      type: 'string',
      required: false
   }
   bEzsigndocumentEzsignform = {
      type: 'boolean',
      required: false
   }
   bEzsigndocumentHassignedsignatures = {
      type: 'boolean',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
   sEzsigndocumentExternalid = {
      type: 'string',
      pattern: '/^.{0,128}$/',
      required: false
   }
   iEzsigndocumentEzsignsignatureattachmenttotal = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigndocumentEzsigndiscussiontotal = {
      type: 'integer',
      required: true
   }
} 


