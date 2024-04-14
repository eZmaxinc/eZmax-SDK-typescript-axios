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
import { EzsigntemplatesignatureRequestCompound } from './ezsigntemplatesignature-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatesignature
 * @export
 * @interface EzsigntemplatesignatureCreateObjectV1Request
 */
export interface EzsigntemplatesignatureCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatesignatureRequestCompound>}
     * @memberof EzsigntemplatesignatureCreateObjectV1Request
     */
    /*'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureRequestCompound>;*/
    'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignatureCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureCreateObjectV1Request
 */
export class DataObjectEzsigntemplatesignatureCreateObjectV1Request {
   a_objEzsigntemplatesignature:Array<EzsigntemplatesignatureRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatesignatureCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatesignatureCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplatesignatureCreateObjectV1Request {
   a_objEzsigntemplatesignature = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


