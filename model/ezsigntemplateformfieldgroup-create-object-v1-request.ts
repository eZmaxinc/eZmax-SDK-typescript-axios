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
import type { EzsigntemplateformfieldgroupRequestCompound } from './ezsigntemplateformfieldgroup-request-compound';

/**
 * Request for POST /1/object/ezsigntemplateformfieldgroup
 * @export
 * @interface EzsigntemplateformfieldgroupCreateObjectV1Request
 */
export interface EzsigntemplateformfieldgroupCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1Request
     */
    /*'a_objEzsigntemplateformfieldgroup': Array<EzsigntemplateformfieldgroupRequestCompound>;*/
    'a_objEzsigntemplateformfieldgroup': Array<EzsigntemplateformfieldgroupRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupCreateObjectV1Request
 */
export class DataObjectEzsigntemplateformfieldgroupCreateObjectV1Request {
   a_objEzsigntemplateformfieldgroup:Array<EzsigntemplateformfieldgroupRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1Request {
   a_objEzsigntemplateformfieldgroup = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


