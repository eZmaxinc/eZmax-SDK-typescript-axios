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



/**
 * A Ezsignformfieldgroupsigner Object
 * @export
 * @interface EzsignformfieldgroupsignerRequest
 */
export interface EzsignformfieldgroupsignerRequest {
    /**
     * The unique ID of the Ezsignformfieldgroupsigner
     * @type {number}
     * @memberof EzsignformfieldgroupsignerRequest
     */
    'pkiEzsignformfieldgroupsignerID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignformfieldgroupsignerRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldgroupsignerRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupsignerRequest
 */
export class DataObjectEzsignformfieldgroupsignerRequest {
   pkiEzsignformfieldgroupsignerID?:number = undefined
   fkiEzsignfoldersignerassociationID:number = 0
}

/**
 * @export 
 * A EzsignformfieldgroupsignerRequest Validation Object
 * @class ValidationObjectEzsignformfieldgroupsignerRequest
 */
export class ValidationObjectEzsignformfieldgroupsignerRequest {
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


