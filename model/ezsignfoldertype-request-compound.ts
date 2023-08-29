/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
 * @type EzsignfoldertypeRequestCompound
 * A Ezsignfoldertype Object and children
 * @export
 */
export type EzsignfoldertypeRequestCompound = EzsignfoldertypeRequest;



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
 * A EzsignfoldertypeRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeRequestCompound
 */
export class DataObjectEzsignfoldertypeRequestCompound {
    pkiEzsignfoldertypeID?:number = undefined
    objEzsignfoldertypeName:MultilingualEzsignfoldertypeName = new DataObjectMultilingualEzsignfoldertypeName()
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

/**
 * @export 
 * A EzsignfoldertypeRequestCompound Validation Object
 * @class ValidationObjectEzsignfoldertypeRequestCompound
 */
export class ValidationObjectEzsignfoldertypeRequestCompound {
   pkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
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
   sEmailAddressSigned = {
      type: 'string',
      required: false
   }
   sEmailAddressSummary = {
      type: 'string',
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
   bEzsignfoldertypeSendattatchmentsigner = {
      type: 'boolean',
      required: true
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
   bEzsignfoldertypeIncludeproofsigner = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeIncludeproofuser = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldertypeIsactive = {
      type: 'boolean',
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


