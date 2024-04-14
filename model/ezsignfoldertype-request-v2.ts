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
import { FieldEEzsignfoldertypeCompletion } from './field-eezsignfoldertype-completion';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypeDisposal } from './field-eezsignfoldertype-disposal';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypeSendreminderfrequency } from './field-eezsignfoldertype-sendreminderfrequency';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualEzsignfoldertypeName } from './multilingual-ezsignfoldertype-name';

/**
 * A Ezsignfoldertype Object
 * @export
 * @interface EzsignfoldertypeRequestV2
 */
export interface EzsignfoldertypeRequestV2 {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'pkiEzsignfoldertypeID'?: number;*/
    'pkiEzsignfoldertypeID'?: number;
    /**
     * 
     * @type {MultilingualEzsignfoldertypeName}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'objEzsignfoldertypeName': MultilingualEzsignfoldertypeName;*/
    'objEzsignfoldertypeName': MultilingualEzsignfoldertypeName;
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'fkiBrandingID': number;*/
    'fkiBrandingID': number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'fkiBillingentityinternalID'?: number;*/
    'fkiBillingentityinternalID'?: number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'fkiEzsigntsarequirementID'?: number;*/
    'fkiEzsigntsarequirementID'?: number;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'a_fkiUserlogintypeID': Array<number>;*/
    'a_fkiUserlogintypeID': Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'a_fkiUsergroupIDAll'?: Array<number>;*/
    'a_fkiUsergroupIDAll'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'a_fkiUsergroupIDRestricted'?: Array<number>;*/
    'a_fkiUsergroupIDRestricted'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'a_fkiUsergroupIDTemplate'?: Array<number>;*/
    'a_fkiUsergroupIDTemplate'?: Array<number>;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'sEmailAddressSigned'?: string;*/
    'sEmailAddressSigned'?: string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'sEmailAddressSummary'?: string;*/
    'sEmailAddressSummary'?: string;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;*/
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * 
     * @type {FieldEEzsignfoldertypeSendreminderfrequency}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'eEzsignfoldertypeSendreminderfrequency'?: FieldEEzsignfoldertypeSendreminderfrequency;*/
    'eEzsignfoldertypeSendreminderfrequency'?: FieldEEzsignfoldertypeSendreminderfrequency;
    /**
     * The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'iEzsignfoldertypeArchivaldays': number;*/
    'iEzsignfoldertypeArchivaldays': number;
    /**
     * 
     * @type {FieldEEzsignfoldertypeDisposal}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'eEzsignfoldertypeDisposal': FieldEEzsignfoldertypeDisposal;*/
    'eEzsignfoldertypeDisposal': FieldEEzsignfoldertypeDisposal;
    /**
     * 
     * @type {FieldEEzsignfoldertypeCompletion}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'eEzsignfoldertypeCompletion': FieldEEzsignfoldertypeCompletion;*/
    'eEzsignfoldertypeCompletion': FieldEEzsignfoldertypeCompletion;
    /**
     * The number of days after the archival before the disposal of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'iEzsignfoldertypeDisposaldays'?: number;*/
    'iEzsignfoldertypeDisposaldays'?: number;
    /**
     * The number of days to get all Ezsignsignatures
     * @type {number}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'iEzsignfoldertypeDeadlinedays': number;*/
    'iEzsignfoldertypeDeadlinedays': number;
    /**
     * Wheter if delegation of signature is allowed to another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeDelegate'?: boolean;*/
    'bEzsignfoldertypeDelegate'?: boolean;
    /**
     * Wheter if creating a new Discussion is allowed or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeDiscussion'?: boolean;*/
    'bEzsignfoldertypeDiscussion'?: boolean;
    /**
     * Wheter if Reassignment of signature is allowed by a signatory to another signatory or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeReassignezsignsigner'?: boolean;*/
    'bEzsignfoldertypeReassignezsignsigner'?: boolean;
    /**
     * Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeReassignuser'?: boolean;*/
    'bEzsignfoldertypeReassignuser'?: boolean;
    /**
     * Whether we send an email to Ezsignsigner  when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtoezsignsigner'?: boolean;*/
    'bEzsignfoldertypeSendsignedtoezsignsigner'?: boolean;
    /**
     * Whether we send an email to User who signed when document is completed
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtouser'?: boolean;*/
    'bEzsignfoldertypeSendsignedtouser'?: boolean;
    /**
     * Whether we send the Ezsigndocument in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendattachmentezsignsigner'?: boolean;*/
    'bEzsignfoldertypeSendattachmentezsignsigner'?: boolean;
    /**
     * Whether we send the proof in the email to Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendproofezsignsigner'?: boolean;*/
    'bEzsignfoldertypeSendproofezsignsigner'?: boolean;
    /**
     * Whether we send the Ezsigndocument in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendattachmentuser'?: boolean;*/
    'bEzsignfoldertypeSendattachmentuser'?: boolean;
    /**
     * Whether we send the proof in the email to User
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendproofuser'?: boolean;*/
    'bEzsignfoldertypeSendproofuser'?: boolean;
    /**
     * Whether we send the proof in the email to external recipient
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendproofemail'?: boolean;*/
    'bEzsignfoldertypeSendproofemail'?: boolean;
    /**
     * Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeAllowdownloadattachmentezsignsigner'?: boolean;*/
    'bEzsignfoldertypeAllowdownloadattachmentezsignsigner'?: boolean;
    /**
     * Whether we allow the proof to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeAllowdownloadproofezsignsigner'?: boolean;*/
    'bEzsignfoldertypeAllowdownloadproofezsignsigner'?: boolean;
    /**
     * Whether we send the proof to user and Ezsignsigner who receive all documents.
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendproofreceivealldocument'?: boolean;*/
    'bEzsignfoldertypeSendproofreceivealldocument'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtodocumentowner': boolean;*/
    'bEzsignfoldertypeSendsignedtodocumentowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtofolderowner': boolean;*/
    'bEzsignfoldertypeSendsignedtofolderowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtofullgroup'?: boolean;*/
    'bEzsignfoldertypeSendsignedtofullgroup'?: boolean;
    /**
     * THIS FIELD WILL BE DELETED. Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtolimitedgroup'?: boolean;*/
    'bEzsignfoldertypeSendsignedtolimitedgroup'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsignedtocolleague': boolean;*/
    'bEzsignfoldertypeSendsignedtocolleague': boolean;
    /**
     * Whether we send the summary to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsummarytodocumentowner': boolean;*/
    'bEzsignfoldertypeSendsummarytodocumentowner': boolean;
    /**
     * Whether we send the summary to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsummarytofolderowner': boolean;*/
    'bEzsignfoldertypeSendsummarytofolderowner': boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsummarytofullgroup'?: boolean;*/
    'bEzsignfoldertypeSendsummarytofullgroup'?: boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsummarytolimitedgroup'?: boolean;*/
    'bEzsignfoldertypeSendsummarytolimitedgroup'?: boolean;
    /**
     * Whether we send the summary to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeSendsummarytocolleague': boolean;*/
    'bEzsignfoldertypeSendsummarytocolleague': boolean;
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequestV2
     */
    /*'bEzsignfoldertypeIsactive': boolean;*/
    'bEzsignfoldertypeIsactive': boolean;
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
 * A EzsignfoldertypeRequestV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeRequestV2
 */
export class DataObjectEzsignfoldertypeRequestV2 {
   pkiEzsignfoldertypeID?:number = undefined
   objEzsignfoldertypeName:MultilingualEzsignfoldertypeName = new DataObjectMultilingualEzsignfoldertypeName()
   fkiBrandingID:number = 0
   fkiBillingentityinternalID?:number = undefined
   fkiEzsigntsarequirementID?:number = undefined
   a_fkiUserlogintypeID:Array<number> = []
   a_fkiUsergroupIDAll?:Array<number> = undefined
   a_fkiUsergroupIDRestricted?:Array<number> = undefined
   a_fkiUsergroupIDTemplate?:Array<number> = undefined
   sEmailAddressSigned?:string = undefined
   sEmailAddressSummary?:string = undefined
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   eEzsignfoldertypeSendreminderfrequency?:FieldEEzsignfoldertypeSendreminderfrequency = undefined
   iEzsignfoldertypeArchivaldays:number = 0
   eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal = 'No'
   eEzsignfoldertypeCompletion:FieldEEzsignfoldertypeCompletion = 'PerEzsigndocument'
   iEzsignfoldertypeDisposaldays?:number = undefined
   iEzsignfoldertypeDeadlinedays:number = 0
   bEzsignfoldertypeDelegate?:boolean = undefined
   bEzsignfoldertypeDiscussion?:boolean = undefined
   bEzsignfoldertypeReassignezsignsigner?:boolean = undefined
   bEzsignfoldertypeReassignuser?:boolean = undefined
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
}

/**
 * @export 
 * A EzsignfoldertypeRequestV2 Validation Object
 * @class ValidationObjectEzsignfoldertypeRequestV2
 */
export class ValidationObjectEzsignfoldertypeRequestV2 {
   pkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
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
   a_fkiUserlogintypeID = {
      type: 'array',
      required: true
   }
   a_fkiUsergroupIDAll = {
      type: 'array',
      required: false
   }
   a_fkiUsergroupIDRestricted = {
      type: 'array',
      required: false
   }
   a_fkiUsergroupIDTemplate = {
      type: 'array',
      required: false
   }
   sEmailAddressSigned = {
      type: 'string',
      pattern: '/^[\w.%+\-!#$%&amp;&#39;*+\\/&#x3D;?^&#x60;{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/',
      required: false
   }
   sEmailAddressSummary = {
      type: 'string',
      pattern: '/^[\w.%+\-!#$%&amp;&#39;*+\\/&#x3D;?^&#x60;{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/',
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
} 

