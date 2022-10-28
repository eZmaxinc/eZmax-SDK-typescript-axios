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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderResponse } from './ezsignfolder-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderStep } from './field-eezsignfolder-step';

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderResponseCompound
 * An Ezsignfolder Object and children to create a complete structure
 * @export
 */
export type EzsignfolderResponseCompound = EzsignfolderResponse;


/**
 * @export 
 * A EzsignfolderResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderResponseCompound
 */
export class DefaultObjectEzsignfolderResponseCompound extends DefaultObject {
   pkiEzsignfolderID:number = 0
   fkiEzsignfoldertypeID:number = 0
   sEzsignfoldertypeNameX:string = ''
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   fkiEzsigntsarequirementID:number = 0
   sEzsigntsarequirementDescriptionX:string = ''
   sEzsignfolderDescription:string = ''
   tEzsignfolderNote:string = ''
   bEzsignfolderIsdisposable:boolean = false
   eEzsignfolderSendreminderfrequency:FieldEEzsignfolderSendreminderfrequency = 'None'
   dtEzsignfolderDuedate?:string = undefined
   dtEzsignfolderSentdate?:string = undefined
   dtEzsignfolderScheduledarchive?:string = undefined
   dtEzsignfolderScheduleddispose?:string = undefined
   eEzsignfolderStep:FieldEEzsignfolderStep = 'Unsent'
   dtEzsignfolderClose?:string = undefined
   tEzsignfolderMessage:string = ''
   objAudit:Partial<CommonAudit> = {}
}


