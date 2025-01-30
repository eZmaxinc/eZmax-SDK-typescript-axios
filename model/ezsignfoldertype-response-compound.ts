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
import type { EzsignfoldertypeResponse } from './ezsignfoldertype-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeCompletion } from './field-eezsignfoldertype-completion';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeDisposal } from './field-eezsignfoldertype-disposal';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeSendreminderfrequency } from './field-eezsignfoldertype-sendreminderfrequency';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignfoldertypeName } from './multilingual-ezsignfoldertype-name';
// May contain unused imports in some cases
// @ts-ignore
import type { UserlogintypeResponse } from './userlogintype-response';

/**
 * @type EzsignfoldertypeResponseCompound
 * A Ezsignfoldertype Object
 * @export
 */
/*export type EzsignfoldertypeResponseCompound = EzsignfoldertypeResponse;*/
export interface EzsignfoldertypeResponseCompound {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    pkiEzsignfoldertypeID:number 
    /**
     * 
     * @type {MultilingualEzsignfoldertypeName}
     * @memberof EzsignfoldertypeResponseCompound
     */
    objEzsignfoldertypeName:MultilingualEzsignfoldertypeName 
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    fkiBrandingID:number 
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    fkiBillingentityinternalID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    fkiUsergroupID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    fkiUsergroupIDRestricted?:number 
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    fkiEzsigntsarequirementID?:number 
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sBrandingDescriptionX:string 
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sBillingentityinternalDescriptionX?:string 
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sEzsigntsarequirementDescriptionX?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sEmailAddressSigned?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sEmailAddressSummary?:string 
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sUsergroupNameX?:string 
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponseCompound
     */
    sUsergroupNameXRestricted?:string 
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeResponseCompound
     */
    eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel 
    /**
     * 
     * @type {FieldEEzsignfoldertypeSendreminderfrequency}
     * @memberof EzsignfoldertypeResponseCompound
     */
    eEzsignfoldertypeSendreminderfrequency?:FieldEEzsignfoldertypeSendreminderfrequency 
    /**
     * The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    iEzsignfoldertypeArchivaldays:number 
    /**
     * 
     * @type {FieldEEzsignfoldertypeDisposal}
     * @memberof EzsignfoldertypeResponseCompound
     */
    eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal 
    /**
     * 
     * @type {FieldEEzsignfoldertypeCompletion}
     * @memberof EzsignfoldertypeResponseCompound
     */
    eEzsignfoldertypeCompletion:FieldEEzsignfoldertypeCompletion 
    /**
     * The number of days after the archival before the disposal of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    iEzsignfoldertypeDisposaldays?:number 
    /**
     * The number of days to get all Ezsignsignatures
     * @type {number}
     * @memberof EzsignfoldertypeResponseCompound
     */
    iEzsignfoldertypeDeadlinedays:number 
    /**
     * Whether we allow the automatic signature by an User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeAutomaticsignature?:boolean 
    /**
     * Wheter if delegation of signature is allowed to another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeDelegate?:boolean 
    /**
     * Wheter if creating a new Discussion is allowed or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeDiscussion?:boolean 
    /**
     * Wheter if Reassignment of signature is allowed by a signatory to another signatory or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeReassignezsignsigner?:boolean 
    /**
     * Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeReassignuser?:boolean 
    /**
     * Wheter if Reassignment of signatures of the groups to which the user belongs is authorized by a user to himself
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeReassigngroup?:boolean 
    /**
     * Whether we send an email to Ezsignsigner  when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtoezsignsigner?:boolean 
    /**
     * Whether we send an email to User who signed when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtouser?:boolean 
    /**
     * Whether we send the Ezsigndocument in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendattachmentezsignsigner?:boolean 
    /**
     * Whether we send the proof in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendproofezsignsigner?:boolean 
    /**
     * Whether we send the Ezsigndocument in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendattachmentuser?:boolean 
    /**
     * Whether we send the proof in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendproofuser?:boolean 
    /**
     * Whether we send the proof in the email to external recipient
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendproofemail?:boolean 
    /**
     * Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner?:boolean 
    /**
     * Whether we allow the proof to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeAllowdownloadproofezsignsigner?:boolean 
    /**
     * Whether we send the proof to user and Ezsignsigner who receive all documents.
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendproofreceivealldocument?:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtodocumentowner:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtofolderowner:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtofullgroup?:boolean 
    /**
     * THIS FIELD WILL BE DELETED. Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtolimitedgroup?:boolean 
    /**
     * Whether we send the signed Ezsigndocument to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsignedtocolleague:boolean 
    /**
     * Whether we send the summary to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsummarytodocumentowner:boolean 
    /**
     * Whether we send the summary to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsummarytofolderowner:boolean 
    /**
     * Whether we send the summary to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsummarytofullgroup?:boolean 
    /**
     * Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsummarytolimitedgroup?:boolean 
    /**
     * Whether we send the summary to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeSendsummarytocolleague:boolean 
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponseCompound
     */
    bEzsignfoldertypeIsactive:boolean 
    /**
     * 
     * @type {Array<UserlogintypeResponse>}
     * @memberof EzsignfoldertypeResponseCompound
     */
    a_objUserlogintype:Array<UserlogintypeResponse> 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeResponseCompound
     */
    a_fkiUserIDSigned?:Array<number> 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeResponseCompound
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
import { ValidationObjectMultilingualEzsignfoldertypeName } from './'

/**
 * @export 
 * A EzsignfoldertypeResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeResponseCompound
 */
export class DataObjectEzsignfoldertypeResponseCompound {
    pkiEzsignfoldertypeID:number = 0
    objEzsignfoldertypeName:MultilingualEzsignfoldertypeName = new DataObjectMultilingualEzsignfoldertypeName()
    fkiBrandingID:number = 0
    fkiBillingentityinternalID?:number = undefined
    fkiUsergroupID?:number = undefined
    fkiUsergroupIDRestricted?:number = undefined
    fkiEzsigntsarequirementID?:number = undefined
    sBrandingDescriptionX:string = ''
    sBillingentityinternalDescriptionX?:string = undefined
    sEzsigntsarequirementDescriptionX?:string = undefined
    sEmailAddressSigned?:string = undefined
    sEmailAddressSummary?:string = undefined
    sUsergroupNameX?:string = undefined
    sUsergroupNameXRestricted?:string = undefined
    eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
    eEzsignfoldertypeSendreminderfrequency?:FieldEEzsignfoldertypeSendreminderfrequency = undefined
    iEzsignfoldertypeArchivaldays:number = 0
    eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal = 'No'
    eEzsignfoldertypeCompletion:FieldEEzsignfoldertypeCompletion = 'PerEzsigndocument'
    iEzsignfoldertypeDisposaldays?:number = undefined
    iEzsignfoldertypeDeadlinedays:number = 0
    bEzsignfoldertypeAutomaticsignature?:boolean = undefined
    bEzsignfoldertypeDelegate?:boolean = undefined
    bEzsignfoldertypeDiscussion?:boolean = undefined
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
    bEzsignfoldertypeIsactive:boolean = false
    a_objUserlogintype:Array<UserlogintypeResponse> = []
    a_fkiUserIDSigned?:Array<number> = undefined
    a_fkiUserIDSummary?:Array<number> = undefined
}

/**
 * @export 
 * A EzsignfoldertypeResponseCompound Validation Object
 * @class ValidationObjectEzsignfoldertypeResponseCompound
 */
export class ValidationObjectEzsignfoldertypeResponseCompound {
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
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiUsergroupIDRestricted = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
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
   sUsergroupNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   sUsergroupNameXRestricted = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   eEzsignfoldertypeSendreminderfrequency = {
      type: 'enum',
      allowableValues: ['None','Daily','Weekly'],
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
   bEzsignfoldertypeIsactive = {
      type: 'boolean',
      required: true
   }
   a_objUserlogintype = {
      type: 'array',
      required: true
   }
   a_fkiUserIDSigned = {
      type: 'array',
      required: false
   }
   a_fkiUserIDSummary = {
      type: 'array',
      required: false
   }
} 


