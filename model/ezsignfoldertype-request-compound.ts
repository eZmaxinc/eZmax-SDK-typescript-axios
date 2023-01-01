/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldertypeRequest } from './ezsignfoldertype-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldertypeRequestCompoundAllOf } from './ezsignfoldertype-request-compound-all-of';
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
 * @type EzsignfoldertypeRequestCompound
 * A Ezsignfoldertype Object and children
 * @export
 */
export type EzsignfoldertypeRequestCompound = EzsignfoldertypeRequest & EzsignfoldertypeRequestCompoundAllOf;


/**
 * @export 
 * A EzsignfoldertypeRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldertypeRequestCompound
 */
export class DefaultObjectEzsignfoldertypeRequestCompound extends DefaultObject {
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
   a_fkiUserIDSigned?:Array<number> = undefined
   a_fkiUserIDSummary?:Array<number> = undefined
}


