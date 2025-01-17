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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { ComputedEEzsignfolderAccess } from './computed-eezsignfolder-access';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomEzsignfoldertypeResponse } from './custom-ezsignfoldertype-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomTimezoneWithCodeResponse } from './custom-timezone-with-code-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfolderResponseV3 } from './ezsignfolder-response-v3';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfolderCompletion } from './field-eezsignfolder-completion';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfolderDocumentdependency } from './field-eezsignfolder-documentdependency';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfolderStep } from './field-eezsignfolder-step';

/**
 * @type EzsignfolderResponseCompoundV3
 * An Ezsignfolder Object and children to create a complete structure
 * @export
 */
/*export type EzsignfolderResponseCompoundV3 = EzsignfolderResponseV3;*/
export interface EzsignfolderResponseCompoundV3 {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    pkiEzsignfolderID:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    fkiEzsignfoldertypeID?:number 
    /**
     * 
     * @type {CustomEzsignfoldertypeResponse}
     * @memberof EzsignfolderResponseCompoundV3
     */
    objEzsignfoldertype?:CustomEzsignfoldertypeResponse 
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    fkiTimezoneID?:number 
    /**
     * 
     * @type {FieldEEzsignfolderCompletion}
     * @memberof EzsignfolderResponseCompoundV3
     */
    eEzsignfolderCompletion:FieldEEzsignfolderCompletion 
    /**
     * 
     * @type {FieldEEzsignfolderDocumentdependency}
     * @memberof EzsignfolderResponseCompoundV3
     */
    eEzsignfolderDocumentdependency?:FieldEEzsignfolderDocumentdependency 
    /**
     * 
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     * @deprecated
     */
    sEzsignfoldertypeNameX?:string 
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    fkiBillingentityinternalID?:number 
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    sBillingentityinternalDescriptionX?:string 
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    fkiEzsigntsarequirementID?:number 
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    sEzsigntsarequirementDescriptionX?:string 
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    sEzsignfolderDescription:string 
    /**
     * Note about the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    tEzsignfolderNote?:string 
    /**
     * If the Ezsigndocument can be disposed
     * @type {boolean}
     * @memberof EzsignfolderResponseCompoundV3
     */
    bEzsignfolderIsdisposable?:boolean 
    /**
     * The number of days before the the first reminder sending
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    iEzsignfolderSendreminderfirstdays?:number 
    /**
     * The number of days after the first reminder sending
     * @type {number}
     * @memberof EzsignfolderResponseCompoundV3
     */
    iEzsignfolderSendreminderotherdays?:number 
    /**
     * The date and time at which the Ezsignfolder will be sent in the future.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderDelayedsenddate?:string 
    /**
     * The maximum date and time at which the Ezsignfolder can be signed.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderDuedate?:string 
    /**
     * The date and time at which the Ezsignfolder was sent the last time.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderSentdate?:string 
    /**
     * The scheduled date and time at which the Ezsignfolder should be archived.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderScheduledarchive?:string 
    /**
     * The scheduled date at which the Ezsignfolder should be Disposed.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderScheduleddispose?:string 
    /**
     * 
     * @type {FieldEEzsignfolderStep}
     * @memberof EzsignfolderResponseCompoundV3
     */
    eEzsignfolderStep?:FieldEEzsignfolderStep 
    /**
     * The date and time at which the Ezsignfolder was closed. Either by applying the last signature or by completing it prematurely.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    dtEzsignfolderClose?:string 
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    tEzsignfolderMessage?:string 
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignfolderResponseCompoundV3
     */
    objAudit?:CommonAudit 
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsignfolderResponseCompoundV3
     */
    sEzsignfolderExternalid?:string 
    /**
     * 
     * @type {ComputedEEzsignfolderAccess}
     * @memberof EzsignfolderResponseCompoundV3
     */
    eEzsignfolderAccess?:ComputedEEzsignfolderAccess 
    /**
     * 
     * @type {CustomTimezoneWithCodeResponse}
     * @memberof EzsignfolderResponseCompoundV3
     */
    objTimezone?:CustomTimezoneWithCodeResponse 
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
import { DataObjectCustomTimezoneWithCodeResponse } from './'
// @ts-ignore
import { ValidationObjectCustomEzsignfoldertypeResponse } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCustomTimezoneWithCodeResponse } from './'

/**
 * @export 
 * A EzsignfolderResponseCompoundV3 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderResponseCompoundV3
 */
export class DataObjectEzsignfolderResponseCompoundV3 {
    pkiEzsignfolderID:number = 0
    fkiEzsignfoldertypeID?:number = undefined
    objEzsignfoldertype?:CustomEzsignfoldertypeResponse = undefined
    fkiTimezoneID?:number = undefined
    eEzsignfolderCompletion:FieldEEzsignfolderCompletion = 'PerEzsigndocument'
    eEzsignfolderDocumentdependency?:FieldEEzsignfolderDocumentdependency = undefined
    sEzsignfoldertypeNameX?:string = undefined
    fkiBillingentityinternalID?:number = undefined
    sBillingentityinternalDescriptionX?:string = undefined
    fkiEzsigntsarequirementID?:number = undefined
    sEzsigntsarequirementDescriptionX?:string = undefined
    sEzsignfolderDescription:string = ''
    tEzsignfolderNote?:string = undefined
    bEzsignfolderIsdisposable?:boolean = undefined
    iEzsignfolderSendreminderfirstdays?:number = undefined
    iEzsignfolderSendreminderotherdays?:number = undefined
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
    eEzsignfolderAccess?:ComputedEEzsignfolderAccess = undefined
    objTimezone?:CustomTimezoneWithCodeResponse = undefined
}

/**
 * @export 
 * A EzsignfolderResponseCompoundV3 Validation Object
 * @class ValidationObjectEzsignfolderResponseCompoundV3
 */
export class ValidationObjectEzsignfolderResponseCompoundV3 {
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
   fkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eEzsignfolderCompletion = {
      type: 'enum',
      allowableValues: ['PerEzsigndocument','PerEzsignfolder'],
      required: true
   }
   eEzsignfolderDocumentdependency = {
      type: 'enum',
      allowableValues: ['All','EzsignsignerOnly'],
      required: false
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
      pattern: /^.{0,75}$/,
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
   iEzsignfolderSendreminderfirstdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   iEzsignfolderSendreminderotherdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
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
      pattern: /^.{0,128}$/,
      required: false
   }
   eEzsignfolderAccess = {
      type: 'enum',
      allowableValues: ['Signer','Read','Modify','Full'],
      required: false
   }
   objTimezone = new ValidationObjectCustomTimezoneWithCodeResponse()
} 


