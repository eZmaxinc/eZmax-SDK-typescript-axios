/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackageResponse } from './ezsigntemplatepackage-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackagemembershipResponseCompound } from './ezsigntemplatepackagemembership-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackagesignerResponseCompound } from './ezsigntemplatepackagesigner-response-compound';

/**
 * @type EzsigntemplatepackageResponseCompound
 * A Ezsigntemplatepackage Object
 * @export
 */
/*export type EzsigntemplatepackageResponseCompound = EzsigntemplatepackageResponse;*/
export interface EzsigntemplatepackageResponseCompound {
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignerResponseCompound>}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerResponseCompound> 
    /**
     * 
     * @type {Array<EzsigntemplatepackagemembershipResponseCompound>}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    a_objEzsigntemplatepackagemembership:Array<EzsigntemplatepackagemembershipResponseCompound> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageResponseCompound
 */
export class DataObjectEzsigntemplatepackageResponseCompound {
    a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerResponseCompound> = []
    a_objEzsigntemplatepackagemembership:Array<EzsigntemplatepackagemembershipResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackageResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackageResponseCompound
 */
export class ValidationObjectEzsigntemplatepackageResponseCompound {
   a_objEzsigntemplatepackagesigner = {
      type: 'array',
      required: true
   }
   a_objEzsigntemplatepackagemembership = {
      type: 'array',
      required: true
   }
} 


