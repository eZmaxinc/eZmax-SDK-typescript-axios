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
import type { EzsignformfieldgroupsignerRequest } from './ezsignformfieldgroupsigner-request';

/**
 * @type EzsignformfieldgroupsignerRequestCompound
 * An Ezsignformfieldgroupsigner Object and children to create a complete structure
 * @export
 */
/*export type EzsignformfieldgroupsignerRequestCompound = EzsignformfieldgroupsignerRequest;*/
export interface EzsignformfieldgroupsignerRequestCompound {
    /**
     * The unique ID of the Ezsignformfieldgroupsigner
     * @type {number}
     * @memberof EzsignformfieldgroupsignerRequestCompound
     */
    pkiEzsignformfieldgroupsignerID?:number 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignformfieldgroupsignerRequestCompound
     */
    fkiEzsignfoldersignerassociationID:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldgroupsignerRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupsignerRequestCompound
 */
export class DataObjectEzsignformfieldgroupsignerRequestCompound {
    pkiEzsignformfieldgroupsignerID?:number = undefined
    fkiEzsignfoldersignerassociationID:number = 0
}

/**
 * @export 
 * A EzsignformfieldgroupsignerRequestCompound Validation Object
 * @class ValidationObjectEzsignformfieldgroupsignerRequestCompound
 */
export class ValidationObjectEzsignformfieldgroupsignerRequestCompound {
   pkiEzsignformfieldgroupsignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


