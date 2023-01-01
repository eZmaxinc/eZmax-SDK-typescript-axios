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
import { EzsignfoldertypeResponseCompound } from './ezsignfoldertype-response-compound';
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
 * @type EzsignfoldertypeGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsignfoldertype/{pkiEzsignfoldertypeID}
 * @export
 */
export type EzsignfoldertypeGetObjectV1ResponseMPayload = EzsignfoldertypeResponseCompound;


/**
 * @export 
 * A EzsignfoldertypeGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldertypeGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsignfoldertypeGetObjectV1ResponseMPayload extends DefaultObject {
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
   a_fkiUserIDSigned?:Array<number> = undefined
   a_fkiUserIDSummary?:Array<number> = undefined
}


