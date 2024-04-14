/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerResponse } from './ezsigntemplatepackagesigner-response';

/**
 * @type EzsigntemplatepackagesignerResponseCompound
 * A Ezsigntemplatepackagesigner Object
 * @export
 */
/*export type EzsigntemplatepackagesignerResponseCompound = EzsigntemplatepackagesignerResponse;*/
export interface EzsigntemplatepackagesignerResponseCompound {
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignerResponseCompound
     */
    pkiEzsigntemplatepackagesignerID:number 
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagesignerResponseCompound
     */
    fkiEzsigntemplatepackageID:number 
    /**
     * The description of the Ezsigntemplatepackagesigner
     * @type {string}
     * @memberof EzsigntemplatepackagesignerResponseCompound
     */
    sEzsigntemplatepackagesignerDescription:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerResponseCompound
 */
export class DataObjectEzsigntemplatepackagesignerResponseCompound {
    pkiEzsigntemplatepackagesignerID:number = 0
    fkiEzsigntemplatepackageID:number = 0
    sEzsigntemplatepackagesignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplatepackagesignerResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerResponseCompound
 */
export class ValidationObjectEzsigntemplatepackagesignerResponseCompound {
   pkiEzsigntemplatepackagesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatepackagesignerDescription = {
      type: 'string',
      required: true
   }
} 


