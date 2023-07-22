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
import { EzsignfolderRequest } from './ezsignfolder-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';

/**
 * @type EzsignfolderRequestCompound
 * An Ezsignfolder Object and children to create a complete structure
 * @export
 */
export type EzsignfolderRequestCompound = EzsignfolderRequest;



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderRequestCompound
 */
export class DataObjectEzsignfolderRequestCompound {
    pkiEzsignfolderID?:number = undefined
    fkiEzsignfoldertypeID:number = 0
    fkiEzsigntsarequirementID?:number = undefined
    sEzsignfolderDescription:string = ''
    tEzsignfolderNote:string = ''
    eEzsignfolderSendreminderfrequency:FieldEEzsignfolderSendreminderfrequency = 'None'
    sEzsignfolderExternalid?:string = undefined
}

/**
 * @export 
 * A EzsignfolderRequestCompound Validation Object
 * @class ValidationObjectEzsignfolderRequestCompound
 */
export class ValidationObjectEzsignfolderRequestCompound {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: false
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   tEzsignfolderNote = {
      type: 'string',
      required: true
   }
   eEzsignfolderSendreminderfrequency = {
      type: 'enum',
      allowableValues: ['None','Daily','Weekly'],
      required: true
   }
   sEzsignfolderExternalid = {
      type: 'string',
      pattern: '/^.{0,64}$/',
      required: false
   }
} 


