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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldertypeResponseV4 } from './ezsignfoldertype-response-v4';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeCompletion } from './field-eezsignfoldertype-completion';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeDisposal } from './field-eezsignfoldertype-disposal';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeDocumentdependency } from './field-eezsignfoldertype-documentdependency';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePdfanoncompliantaction } from './field-eezsignfoldertype-pdfanoncompliantaction';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePdfarequirement } from './field-eezsignfoldertype-pdfarequirement';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeSigneraccess } from './field-eezsignfoldertype-signeraccess';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignfoldertypeName } from './multilingual-ezsignfoldertype-name';
// May contain unused imports in some cases
// @ts-ignore
import type { UsergroupResponse } from './usergroup-response';
// May contain unused imports in some cases
// @ts-ignore
import type { UserlogintypeResponse } from './userlogintype-response';

/**
 * @type EzsignfoldertypeResponseCompoundV4
 * A Ezsignfoldertype Object
 * @export
 */
/*export type EzsignfoldertypeResponseCompoundV4 = EzsignfoldertypeResponseV4;*/
export interface EzsignfoldertypeResponseCompoundV4 {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    pkiEzsignfoldertypeID:number 
    /**
     * 
     * @type {MultilingualEzsignfoldertypeName}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    objEzsignfoldertypeName:MultilingualEzsignfoldertypeName 
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiBrandingID:number 
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiBillingentityinternalID?:number 
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiEzsigntsarequirementID?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiFontIDAnnotation?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiFontIDFormfield?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiFontIDSignature?:number 
    /**
     * The unique ID of the Pdfalevel
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    fkiPdfalevelIDConvert?:number 
    /**
     * 
     * @type {FieldEEzsignfoldertypeDocumentdependency}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypeDocumentdependency?:FieldEEzsignfoldertypeDocumentdependency 
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    sBrandingDescriptionX:string 
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    sBillingentityinternalDescriptionX?:string 
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    sEzsigntsarequirementDescriptionX?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    sEmailAddressSigned?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    sEmailAddressSummary?:string 
    /**
     * 
     * @type {FieldEEzsignfoldertypePdfarequirement}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypePdfarequirement?:FieldEEzsignfoldertypePdfarequirement 
    /**
     * 
     * @type {FieldEEzsignfoldertypePdfanoncompliantaction}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypePdfanoncompliantaction?:FieldEEzsignfoldertypePdfanoncompliantaction 
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel 
    /**
     * Font size for annotations
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeFontsizeannotation?:number 
    /**
     * Font size for form fields
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeFontsizeformfield?:number 
    /**
     * The number of days before the the first reminder sending
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeSendreminderfirstdays?:number 
    /**
     * The number of days after the first reminder sending
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeSendreminderotherdays?:number 
    /**
     * The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeArchivaldays:number 
    /**
     * 
     * @type {FieldEEzsignfoldertypeDisposal}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal 
    /**
     * 
     * @type {FieldEEzsignfoldertypeCompletion}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypeCompletion:FieldEEzsignfoldertypeCompletion 
    /**
     * The number of days after the archival before the disposal of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeDisposaldays?:number 
    /**
     * The number of days to get all Ezsignsignatures
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypeDeadlinedays:number 
    /**
     * Wheter if document will be ended prematurely after Ezsignfolder expires.
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypePrematurelyendautomatically?:boolean 
    /**
     * Number of days between Ezsignfolder expiration and automatic prematurely end of Ezsigndocuments.
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    iEzsignfoldertypePrematurelyendautomaticallydays?:number 
    /**
     * Whether we allow the automatic signature by an User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeAutomaticsignature?:boolean 
    /**
     * Wheter if delegation of signature is allowed to another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeDelegate?:boolean 
    /**
     * Wheter if creating a new Discussion is allowed or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeDiscussion?:boolean 
    /**
     * Whether we log recipient of signed document in proof
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeLogrecipientinproof?:boolean 
    /**
     * Wheter if Reassignment of signature is allowed by a signatory to another signatory or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeReassignezsignsigner?:boolean 
    /**
     * Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeReassignuser?:boolean 
    /**
     * Wheter if Reassignment of signatures of the groups to which the user belongs is authorized by a user to himself
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeReassigngroup?:boolean 
    /**
     * Whether we send an email to Ezsignsigner  when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtoezsignsigner?:boolean 
    /**
     * Whether we send an email to User who signed when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtouser?:boolean 
    /**
     * Whether we send the Ezsigndocument in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendattachmentezsignsigner?:boolean 
    /**
     * Whether we send the proof in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendproofezsignsigner?:boolean 
    /**
     * Whether we send the Ezsigndocument in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendattachmentuser?:boolean 
    /**
     * Whether we send the proof in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendproofuser?:boolean 
    /**
     * Whether we send the proof in the email to external recipient
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendproofemail?:boolean 
    /**
     * Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner?:boolean 
    /**
     * Whether we allow the proof to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeAllowdownloadproofezsignsigner?:boolean 
    /**
     * Whether we send the proof to user and Ezsignsigner who receive all documents.
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendproofreceivealldocument?:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtodocumentowner:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtofolderowner:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtofullgroup?:boolean 
    /**
     * THIS FIELD WILL BE DELETED. Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtolimitedgroup?:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsignedtocolleague:boolean 
    /**
     * Whether we send the summary to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsummarytodocumentowner:boolean 
    /**
     * Whether we send the summary to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsummarytofolderowner:boolean 
    /**
     * Whether we send the summary to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsummarytofullgroup?:boolean 
    /**
     * Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsummarytolimitedgroup?:boolean 
    /**
     * Whether we send the summary to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeSendsummarytocolleague:boolean 
    /**
     * 
     * @type {FieldEEzsignfoldertypeSigneraccess}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    eEzsignfoldertypeSigneraccess?:FieldEEzsignfoldertypeSigneraccess 
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    bEzsignfoldertypeIsactive:boolean 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_fkiPdfalevelID?:Array<number> 
    /**
     * 
     * @type {Array<UserlogintypeResponse>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_objUserlogintype:Array<UserlogintypeResponse> 
    /**
     * 
     * @type {Array<UsergroupResponse>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_objUsergroupAll?:Array<UsergroupResponse> 
    /**
     * 
     * @type {Array<UsergroupResponse>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_objUsergroupRestricted?:Array<UsergroupResponse> 
    /**
     * 
     * @type {Array<UsergroupResponse>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_objUsergroupTemplate?:Array<UsergroupResponse> 
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    objAudit:CommonAudit 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_fkiUserIDSigned?:Array<number> 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeResponseCompoundV4
     */
    a_fkiUserIDSummary?:Array<number> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzsignfoldertypeName } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzsignfoldertypeName } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzsignfoldertypeResponseCompoundV4 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeResponseCompoundV4
 */
export class DataObjectEzsignfoldertypeResponseCompoundV4 {
    pkiEzsignfoldertypeID:number = 0
    objEzsignfoldertypeName:MultilingualEzsignfoldertypeName = new DataObjectMultilingualEzsignfoldertypeName()
    fkiBrandingID:number = 0
    fkiBillingentityinternalID?:number = undefined
    fkiEzsigntsarequirementID?:number = undefined
    fkiFontIDAnnotation?:number = undefined
    fkiFontIDFormfield?:number = undefined
    fkiFontIDSignature?:number = undefined
    fkiPdfalevelIDConvert?:number = undefined
    eEzsignfoldertypeDocumentdependency?:FieldEEzsignfoldertypeDocumentdependency = undefined
    sBrandingDescriptionX:string = ''
    sBillingentityinternalDescriptionX?:string = undefined
    sEzsigntsarequirementDescriptionX?:string = undefined
    sEmailAddressSigned?:string = undefined
    sEmailAddressSummary?:string = undefined
    eEzsignfoldertypePdfarequirement?:FieldEEzsignfoldertypePdfarequirement = undefined
    eEzsignfoldertypePdfanoncompliantaction?:FieldEEzsignfoldertypePdfanoncompliantaction = undefined
    eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
    iEzsignfoldertypeFontsizeannotation?:number = undefined
    iEzsignfoldertypeFontsizeformfield?:number = undefined
    iEzsignfoldertypeSendreminderfirstdays?:number = undefined
    iEzsignfoldertypeSendreminderotherdays?:number = undefined
    iEzsignfoldertypeArchivaldays:number = 0
    eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal = 'No'
    eEzsignfoldertypeCompletion:FieldEEzsignfoldertypeCompletion = 'PerEzsigndocument'
    iEzsignfoldertypeDisposaldays?:number = undefined
    iEzsignfoldertypeDeadlinedays:number = 0
    bEzsignfoldertypePrematurelyendautomatically?:boolean = undefined
    iEzsignfoldertypePrematurelyendautomaticallydays?:number = undefined
    bEzsignfoldertypeAutomaticsignature?:boolean = undefined
    bEzsignfoldertypeDelegate?:boolean = undefined
    bEzsignfoldertypeDiscussion?:boolean = undefined
    bEzsignfoldertypeLogrecipientinproof?:boolean = undefined
    bEzsignfoldertypeReassignezsignsigner?:boolean = undefined
    bEzsignfoldertypeReassignuser?:boolean = undefined
    bEzsignfoldertypeReassigngroup?:boolean = undefined
    bEzsignfoldertypeSendsignedtoezsignsigner?:boolean = undefined
    bEzsignfoldertypeSendsignedtouser?:boolean = undefined
    bEzsignfoldertypeSendattachmentezsignsigner?:boolean = undefined
    bEzsignfoldertypeSendproofezsignsigner?:boolean = undefined
    bEzsignfoldertypeSendattachmentuser?:boolean = undefined
    bEzsignfoldertypeSendproofuser?:boolean = undefined
    bEzsignfoldertypeSendproofemail?:boolean = undefined
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner?:boolean = undefined
    bEzsignfoldertypeAllowdownloadproofezsignsigner?:boolean = undefined
    bEzsignfoldertypeSendproofreceivealldocument?:boolean = undefined
    bEzsignfoldertypeSendsignedtodocumentowner:boolean = false
    bEzsignfoldertypeSendsignedtofolderowner:boolean = false
    bEzsignfoldertypeSendsignedtofullgroup?:boolean = undefined
    bEzsignfoldertypeSendsignedtolimitedgroup?:boolean = undefined
    bEzsignfoldertypeSendsignedtocolleague:boolean = false
    bEzsignfoldertypeSendsummarytodocumentowner:boolean = false
    bEzsignfoldertypeSendsummarytofolderowner:boolean = false
    bEzsignfoldertypeSendsummarytofullgroup?:boolean = undefined
    bEzsignfoldertypeSendsummarytolimitedgroup?:boolean = undefined
    bEzsignfoldertypeSendsummarytocolleague:boolean = false
    eEzsignfoldertypeSigneraccess?:FieldEEzsignfoldertypeSigneraccess = undefined
    bEzsignfoldertypeIsactive:boolean = false
    a_fkiPdfalevelID?:Array<number> = undefined
    a_objUserlogintype:Array<UserlogintypeResponse> = []
    a_objUsergroupAll?:Array<UsergroupResponse> = undefined
    a_objUsergroupRestricted?:Array<UsergroupResponse> = undefined
    a_objUsergroupTemplate?:Array<UsergroupResponse> = undefined
    objAudit:CommonAudit = new DataObjectCommonAudit()
    a_fkiUserIDSigned?:Array<number> = undefined
    a_fkiUserIDSummary?:Array<number> = undefined
}

/**
 * @export 
 * A EzsignfoldertypeResponseCompoundV4 Validation Object
 * @class ValidationObjectEzsignfoldertypeResponseCompoundV4
 */
export class ValidationObjectEzsignfoldertypeResponseCompoundV4 {
   pkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   objEzsignfoldertypeName = new ValidationObjectMultilingualEzsignfoldertypeName()
   fkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: false
   }
   fkiFontIDAnnotation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFontIDFormfield = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFontIDSignature = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiPdfalevelIDConvert = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   eEzsignfoldertypeDocumentdependency = {
      type: 'enum',
      allowableValues: ['All','EzsignsignerOnly'],
      required: false
   }
   sBrandingDescriptionX = {
      type: 'string',
      required: true
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: false
   }
   sEzsigntsarequirementDescriptionX = {
      type: 'string',
      required: false
   }
   sEmailAddressSigned = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: false
   }
   sEmailAddressSummary = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: false
   }
   eEzsignfoldertypePdfarequirement = {
      type: 'enum',
      allowableValues: ['None','Declared','Verified'],
      required: false
   }
   eEzsignfoldertypePdfanoncompliantaction = {
      type: 'enum',
      allowableValues: ['Reject','Convert'],
      required: false
   }
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   iEzsignfoldertypeFontsizeannotation = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: false
   }
   iEzsignfoldertypeFontsizeformfield = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: false
   }
   iEzsignfoldertypeSendreminderfirstdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   iEzsignfoldertypeSendreminderotherdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   iEzsignfoldertypeArchivaldays = {
      type: 'integer',
      minimum: 0,
      maximum: 180,
      required: true
   }
   eEzsignfoldertypeDisposal = {
      type: 'enum',
      allowableValues: ['No','Manual','Automatic'],
      required: true
   }
   eEzsignfoldertypeCompletion = {
      type: 'enum',
      allowableValues: ['PerEzsigndocument','PerEzsignfolder'],
      required: true
   }
   iEzsignfoldertypeDisposaldays = {
      type: 'integer',
      minimum: 0,
      maximum: 9999,
      required: false
   }
   iEzsignfoldertypeDeadlinedays = {
      type: 'integer',
      minimum: 1,
      maximum: 60,
      required: true
   }
   bEzsignfoldertypePrematurelyendautomatically = {
      type: 'boolean',
      required: false
   }
   iEzsignfoldertypePrematurelyendautomaticallydays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   bEzsignfoldertypeAutomaticsignature = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeDelegate = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeDiscussion = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeLogrecipientinproof = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassignezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassignuser = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassigngroup = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsignedtoezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsignedtouser = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendattachmentezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendproofezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendattachmentuser = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendproofuser = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendproofemail = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeAllowdownloadattachmentezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeAllowdownloadproofezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendproofreceivealldocument = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsignedtodocumentowner = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeSendsignedtofolderowner = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeSendsignedtofullgroup = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsignedtolimitedgroup = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsignedtocolleague = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeSendsummarytodocumentowner = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeSendsummarytofolderowner = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeSendsummarytofullgroup = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsummarytolimitedgroup = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeSendsummarytocolleague = {
      type: 'boolean',
      required: true
   }
   eEzsignfoldertypeSigneraccess = {
      type: 'enum',
      allowableValues: ['No','SignerDocuments','AllDocuments'],
      required: false
   }
   bEzsignfoldertypeIsactive = {
      type: 'boolean',
      required: true
   }
   a_fkiPdfalevelID = {
      type: 'array',
      required: false
   }
   a_objUserlogintype = {
      type: 'array',
      required: true
   }
   a_objUsergroupAll = {
      type: 'array',
      required: false
   }
   a_objUsergroupRestricted = {
      type: 'array',
      required: false
   }
   a_objUsergroupTemplate = {
      type: 'array',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
   a_fkiUserIDSigned = {
      type: 'array',
      required: false
   }
   a_fkiUserIDSummary = {
      type: 'array',
      required: false
   }
} 


