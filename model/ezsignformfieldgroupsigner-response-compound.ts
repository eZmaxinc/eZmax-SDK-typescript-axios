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
import type { EzsignformfieldgroupsignerResponse } from './ezsignformfieldgroupsigner-response';

/**
 * @type EzsignformfieldgroupsignerResponseCompound
 * An Ezsignformfieldgroupsigner Object and children to create a complete structure
 * @export
 */
/*export type EzsignformfieldgroupsignerResponseCompound = EzsignformfieldgroupsignerResponse;*/
export interface EzsignformfieldgroupsignerResponseCompound {
    /**
     * The unique ID of the Ezsignformfieldgroupsigner
     * @type {number}
     * @memberof EzsignformfieldgroupsignerResponseCompound
     */
    pkiEzsignformfieldgroupsignerID:number 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignformfieldgroupsignerResponseCompound
     */
    fkiEzsignfoldersignerassociationID:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldgroupsignerResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupsignerResponseCompound
 */
export class DataObjectEzsignformfieldgroupsignerResponseCompound {
    pkiEzsignformfieldgroupsignerID:number = 0
    fkiEzsignfoldersignerassociationID:number = 0
}

/**
 * @export 
 * A EzsignformfieldgroupsignerResponseCompound Validation Object
 * @class ValidationObjectEzsignformfieldgroupsignerResponseCompound
 */
export class ValidationObjectEzsignformfieldgroupsignerResponseCompound {
   pkiEzsignformfieldgroupsignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


