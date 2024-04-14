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
import { CustomEzsignfoldertypeResponse } from './custom-ezsignfoldertype-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderCompletion } from './field-eezsignfolder-completion';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderStep } from './field-eezsignfolder-step';

/**
 * An Ezsignfolder Object
 * @export
 * @interface EzsignfolderResponse
 */
export interface EzsignfolderResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfolderResponse
     */
    /*'pkiEzsignfolderID': number;*/
    'pkiEzsignfolderID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfolderResponse
     */
    /*'fkiEzsignfoldertypeID'?: number;*/
    'fkiEzsignfoldertypeID'?: number;
    /**
     * 
     * @type {CustomEzsignfoldertypeResponse}
     * @memberof EzsignfolderResponse
     */
    /*'objEzsignfoldertype'?: CustomEzsignfoldertypeResponse;*/
    'objEzsignfoldertype'?: CustomEzsignfoldertypeResponse;
    /**
     * 
     * @type {FieldEEzsignfolderCompletion}
     * @memberof EzsignfolderResponse
     */
    /*'eEzsignfolderCompletion': FieldEEzsignfolderCompletion;*/
    'eEzsignfolderCompletion': FieldEEzsignfolderCompletion;
    /**
     * 
     * @type {string}
     * @memberof EzsignfolderResponse
     * @deprecated
     */
    /*'sEzsignfoldertypeNameX'?: string;*/
    'sEzsignfoldertypeNameX'?: string;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfolderResponse
     */
    /*'fkiBillingentityinternalID'?: number;*/
    'fkiBillingentityinternalID'?: number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'sBillingentityinternalDescriptionX'?: string;*/
    'sBillingentityinternalDescriptionX'?: string;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderResponse
     */
    /*'fkiEzsigntsarequirementID'?: number;*/
    'fkiEzsigntsarequirementID'?: number;
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'sEzsigntsarequirementDescriptionX'?: string;*/
    'sEzsigntsarequirementDescriptionX'?: string;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * Note about the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'tEzsignfolderNote'?: string;*/
    'tEzsignfolderNote'?: string;
    /**
     * If the Ezsigndocument can be disposed
     * @type {boolean}
     * @memberof EzsignfolderResponse
     */
    /*'bEzsignfolderIsdisposable'?: boolean;*/
    'bEzsignfolderIsdisposable'?: boolean;
    /**
     * 
     * @type {FieldEEzsignfolderSendreminderfrequency}
     * @memberof EzsignfolderResponse
     */
    /*'eEzsignfolderSendreminderfrequency'?: FieldEEzsignfolderSendreminderfrequency;*/
    'eEzsignfolderSendreminderfrequency'?: FieldEEzsignfolderSendreminderfrequency;
    /**
     * The date and time at which the Ezsignfolder will be sent in the future.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderDelayedsenddate'?: string;*/
    'dtEzsignfolderDelayedsenddate'?: string;
    /**
     * The maximum date and time at which the Ezsignfolder can be signed.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderDuedate'?: string;*/
    'dtEzsignfolderDuedate'?: string;
    /**
     * The date and time at which the Ezsignfolder was sent the last time.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderSentdate'?: string;*/
    'dtEzsignfolderSentdate'?: string;
    /**
     * The scheduled date and time at which the Ezsignfolder should be archived.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderScheduledarchive'?: string;*/
    'dtEzsignfolderScheduledarchive'?: string;
    /**
     * The scheduled date at which the Ezsignfolder should be Disposed.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderScheduleddispose'?: string;*/
    'dtEzsignfolderScheduleddispose'?: string;
    /**
     * 
     * @type {FieldEEzsignfolderStep}
     * @memberof EzsignfolderResponse
     */
    /*'eEzsignfolderStep'?: FieldEEzsignfolderStep;*/
    'eEzsignfolderStep'?: FieldEEzsignfolderStep;
    /**
     * The date and time at which the Ezsignfolder was closed. Either by applying the last signature or by completing it prematurely.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'dtEzsignfolderClose'?: string;*/
    'dtEzsignfolderClose'?: string;
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'tEzsignfolderMessage'?: string;*/
    'tEzsignfolderMessage'?: string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignfolderResponse
     */
    /*'objAudit'?: CommonAudit;*/
    'objAudit'?: CommonAudit;
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsignfolderResponse
     */
    /*'sEzsignfolderExternalid'?: string;*/
    'sEzsignfolderExternalid'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomEzsignfoldertypeResponse } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCustomEzsignfoldertypeResponse } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzsignfolderResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderResponse
 */
export class DataObjectEzsignfolderResponse {
   pkiEzsignfolderID:number = 0
   fkiEzsignfoldertypeID?:number = undefined
   objEzsignfoldertype?:CustomEzsignfoldertypeResponse = undefined
   eEzsignfolderCompletion:FieldEEzsignfolderCompletion = 'PerEzsigndocument'
   sEzsignfoldertypeNameX?:string = undefined
   fkiBillingentityinternalID?:number = undefined
   sBillingentityinternalDescriptionX?:string = undefined
   fkiEzsigntsarequirementID?:number = undefined
   sEzsigntsarequirementDescriptionX?:string = undefined
   sEzsignfolderDescription:string = ''
   tEzsignfolderNote?:string = undefined
   bEzsignfolderIsdisposable?:boolean = undefined
   eEzsignfolderSendreminderfrequency?:FieldEEzsignfolderSendreminderfrequency = undefined
   dtEzsignfolderDelayedsenddate?:string = undefined
   dtEzsignfolderDuedate?:string = undefined
   dtEzsignfolderSentdate?:string = undefined
   dtEzsignfolderScheduledarchive?:string = undefined
   dtEzsignfolderScheduleddispose?:string = undefined
   eEzsignfolderStep?:FieldEEzsignfolderStep = undefined
   dtEzsignfolderClose?:string = undefined
   tEzsignfolderMessage?:string = undefined
   objAudit?:CommonAudit = undefined
   sEzsignfolderExternalid?:string = undefined
}

/**
 * @export 
 * A EzsignfolderResponse Validation Object
 * @class ValidationObjectEzsignfolderResponse
 */
export class ValidationObjectEzsignfolderResponse {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   objEzsignfoldertype = new ValidationObjectCustomEzsignfoldertypeResponse()
   eEzsignfolderCompletion = {
      type: 'enum',
      allowableValues: ['PerEzsigndocument','PerEzsignfolder'],
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: false
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: false
   }
   sEzsigntsarequirementDescriptionX = {
      type: 'string',
      required: false
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   tEzsignfolderNote = {
      type: 'string',
      required: false
   }
   bEzsignfolderIsdisposable = {
      type: 'boolean',
      required: false
   }
   eEzsignfolderSendreminderfrequency = {
      type: 'enum',
      allowableValues: ['None','Daily','Weekly'],
      required: false
   }
   dtEzsignfolderDelayedsenddate = {
      type: 'string',
      required: false
   }
   dtEzsignfolderDuedate = {
      type: 'string',
      required: false
   }
   dtEzsignfolderSentdate = {
      type: 'string',
      required: false
   }
   dtEzsignfolderScheduledarchive = {
      type: 'string',
      required: false
   }
   dtEzsignfolderScheduleddispose = {
      type: 'string',
      required: false
   }
   eEzsignfolderStep = {
      type: 'enum',
      allowableValues: ['Unsent','PendingSend','Sent','PartiallySigned','Expired','Completed','Archived','Disposed'],
      required: false
   }
   dtEzsignfolderClose = {
      type: 'string',
      required: false
   }
   tEzsignfolderMessage = {
      type: 'string',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
   sEzsignfolderExternalid = {
      type: 'string',
      pattern: '/^.{0,128}$/',
      required: false
   }
} 


