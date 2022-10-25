/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


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

import { DefaultObject } from '../base'

/**
 * A Ezsignfoldertype Object
 * @export
 * @interface EzsignfoldertypeRequest
 */
export interface EzsignfoldertypeRequest {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'pkiEzsignfoldertypeID'?: number;
    /**
     * 
     * @type {MultilingualEzsignfoldertypeName}
     * @memberof EzsignfoldertypeRequest
     */
    'objEzsignfoldertypeName': MultilingualEzsignfoldertypeName;
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'fkiBrandingID': number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'fkiBillingentityinternalID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'fkiUsergroupID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'fkiUsergroupIDRestricted'?: number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'fkiEzsigntsarequirementID'?: number;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeRequest
     */
    'sEmailAddressSigned'?: string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeRequest
     */
    'sEmailAddressSummary'?: string;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeRequest
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * 
     * @type {FieldEEzsignfoldertypeSendreminderfrequency}
     * @memberof EzsignfoldertypeRequest
     */
    'eEzsignfoldertypeSendreminderfrequency'?: FieldEEzsignfoldertypeSendreminderfrequency;
    /**
     * The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'iEzsignfoldertypeArchivaldays': number;
    /**
     * 
     * @type {FieldEEzsignfoldertypeDisposal}
     * @memberof EzsignfoldertypeRequest
     */
    'eEzsignfoldertypeDisposal': FieldEEzsignfoldertypeDisposal;
    /**
     * The number of days after the archival before the disposal of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'iEzsignfoldertypeDisposaldays'?: number;
    /**
     * The number of days to get all Ezsignsignatures
     * @type {number}
     * @memberof EzsignfoldertypeRequest
     */
    'iEzsignfoldertypeDeadlinedays': number;
    /**
     * Whether we send the Ezsigndocument and the proof as attachment in the email
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendattatchmentsigner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsignedtodocumentowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsignedtofolderowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsignedtofullgroup'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsignedtolimitedgroup'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsignedtocolleague': boolean;
    /**
     * Whether we send the summary to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsummarytodocumentowner': boolean;
    /**
     * Whether we send the summary to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsummarytofolderowner': boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsummarytofullgroup'?: boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsummarytolimitedgroup'?: boolean;
    /**
     * Whether we send the summary to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeSendsummarytocolleague': boolean;
    /**
     * Whether we include the proof with the signed Ezsigndocument for Ezsignsigners
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeIncludeproofsigner': boolean;
    /**
     * Whether we include the proof with the signed Ezsigndocument for users
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeIncludeproofuser': boolean;
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeRequest
     */
    'bEzsignfoldertypeIsactive': boolean;
}
/**
 * A EzsignfoldertypeRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldertypeRequest
 */
export class DefaultObjectEzsignfoldertypeRequest extends DefaultObject {
   pkiEzsignfoldertypeID?:number = undefined
   objEzsignfoldertypeName:Partial<MultilingualEzsignfoldertypeName> = {}
   fkiBrandingID:number = 0
   fkiBillingentityinternalID?:number = undefined
   fkiUsergroupID?:number = undefined
   fkiUsergroupIDRestricted?:number = undefined
   fkiEzsigntsarequirementID?:number = undefined
   sEmailAddressSigned?:string = undefined
   sEmailAddressSummary?:string = undefined
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   eEzsignfoldertypeSendreminderfrequency?:FieldEEzsignfoldertypeSendreminderfrequency = undefined
   iEzsignfoldertypeArchivaldays:number = 0
   eEzsignfoldertypeDisposal:FieldEEzsignfoldertypeDisposal = 'No'
   iEzsignfoldertypeDisposaldays?:number = undefined
   iEzsignfoldertypeDeadlinedays:number = 0
   bEzsignfoldertypeSendattatchmentsigner:boolean = false
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
   bEzsignfoldertypeIncludeproofsigner:boolean = false
   bEzsignfoldertypeIncludeproofuser:boolean = false
   bEzsignfoldertypeIsactive:boolean = false
}


