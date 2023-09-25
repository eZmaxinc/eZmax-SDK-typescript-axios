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
import { EzsigntemplatepackageRequestCompound } from './ezsigntemplatepackage-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatepackage
 * @export
 * @interface EzsigntemplatepackageCreateObjectV1Request
 */
export interface EzsigntemplatepackageCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatepackageRequestCompound>}
     * @memberof EzsigntemplatepackageCreateObjectV1Request
     */
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageCreateObjectV1Request
 */
export class DataObjectEzsigntemplatepackageCreateObjectV1Request {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackageCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatepackageCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplatepackageCreateObjectV1Request {
   a_objEzsigntemplatepackage = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


