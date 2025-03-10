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
import type { EzsigntemplatesignerRequestCompound } from './ezsigntemplatesigner-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatesigner
 * @export
 * @interface EzsigntemplatesignerCreateObjectV1Request
 */
export interface EzsigntemplatesignerCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatesignerRequestCompound>}
     * @memberof EzsigntemplatesignerCreateObjectV1Request
     */
    /*'a_objEzsigntemplatesigner': Array<EzsigntemplatesignerRequestCompound>;*/
    'a_objEzsigntemplatesigner': Array<EzsigntemplatesignerRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignerCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerCreateObjectV1Request
 */
export class DataObjectEzsigntemplatesignerCreateObjectV1Request {
   a_objEzsigntemplatesigner:Array<EzsigntemplatesignerRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatesignerCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatesignerCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplatesignerCreateObjectV1Request {
   a_objEzsigntemplatesigner = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


