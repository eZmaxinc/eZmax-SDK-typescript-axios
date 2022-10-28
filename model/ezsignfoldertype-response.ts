/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
 * @interface EzsignfoldertypeResponse
 */
export interface EzsignfoldertypeResponse {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'pkiEzsignfoldertypeID': number;
    /**
     * 
     * @type {MultilingualEzsignfoldertypeName}
     * @memberof EzsignfoldertypeResponse
     */
    'objEzsignfoldertypeName': MultilingualEzsignfoldertypeName;
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'fkiBrandingID': number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'fkiBillingentityinternalID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'fkiUsergroupID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'fkiUsergroupIDRestricted'?: number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'fkiEzsigntsarequirementID'?: number;
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sBrandingDescriptionX': string;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sBillingentityinternalDescriptionX'?: string;
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sEzsigntsarequirementDescriptionX'?: string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sEmailAddressSigned'?: string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sEmailAddressSummary'?: string;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sUsergroupNameX'?: string;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeResponse
     */
    'sUsergroupNameXRestricted'?: string;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeResponse
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * 
     * @type {FieldEEzsignfoldertypeSendreminderfrequency}
     * @memberof EzsignfoldertypeResponse
     */
    'eEzsignfoldertypeSendreminderfrequency'?: FieldEEzsignfoldertypeSendreminderfrequency;
    /**
     * The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'iEzsignfoldertypeArchivaldays': number;
    /**
     * 
     * @type {FieldEEzsignfoldertypeDisposal}
     * @memberof EzsignfoldertypeResponse
     */
    'eEzsignfoldertypeDisposal': FieldEEzsignfoldertypeDisposal;
    /**
     * The number of days after the archival before the disposal of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'iEzsignfoldertypeDisposaldays'?: number;
    /**
     * The number of days to get all Ezsignsignatures
     * @type {number}
     * @memberof EzsignfoldertypeResponse
     */
    'iEzsignfoldertypeDeadlinedays': number;
    /**
     * Whether we send the Ezsigndocument and the proof as attachment in the email
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendattatchmentsigner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsignedtodocumentowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsignedtofolderowner': boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsignedtofullgroup'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsignedtolimitedgroup'?: boolean;
    /**
     * Whether we send the signed Ezsigndocument to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsignedtocolleague': boolean;
    /**
     * Whether we send the summary to the Ezsigndocument\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsummarytodocumentowner': boolean;
    /**
     * Whether we send the summary to the Ezsignfolder\'s owner
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsummarytofolderowner': boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to all Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsummarytofullgroup'?: boolean;
    /**
     * Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsummarytolimitedgroup'?: boolean;
    /**
     * Whether we send the summary to the colleagues
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeSendsummarytocolleague': boolean;
    /**
     * Whether we include the proof with the signed Ezsigndocument for Ezsignsigners
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeIncludeproofsigner': boolean;
    /**
     * Whether we include the proof with the signed Ezsigndocument for users
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeIncludeproofuser': boolean;
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeResponse
     */
    'bEzsignfoldertypeIsactive': boolean;
}
/**
 * A EzsignfoldertypeResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldertypeResponse
 */
export class DefaultObjectEzsignfoldertypeResponse extends DefaultObject {
   pkiEzsignfoldertypeID:number = 0
   objEzsignfoldertypeName:Partial<MultilingualEzsignfoldertypeName> = {}
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


