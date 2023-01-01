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
import { EzsignfolderRequest } from './ezsignfolder-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderRequestCompound
 * An Ezsignfolder Object and children to create a complete structure
 * @export
 */
export type EzsignfolderRequestCompound = EzsignfolderRequest;


/**
 * @export 
 * A EzsignfolderRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderRequestCompound
 */
export class DefaultObjectEzsignfolderRequestCompound extends DefaultObject {
   pkiEzsignfolderID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiEzsigntsarequirementID?:number = undefined
   sEzsignfolderDescription:string = ''
   tEzsignfolderNote:string = ''
   eEzsignfolderSendreminderfrequency:FieldEEzsignfolderSendreminderfrequency = 'None'
}


