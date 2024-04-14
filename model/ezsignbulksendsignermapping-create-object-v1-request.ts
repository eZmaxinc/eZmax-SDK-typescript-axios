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
import { EzsignbulksendsignermappingRequestCompound } from './ezsignbulksendsignermapping-request-compound';

/**
 * Request for POST /1/object/ezsignbulksendsignermapping
 * @export
 * @interface EzsignbulksendsignermappingCreateObjectV1Request
 */
export interface EzsignbulksendsignermappingCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignbulksendsignermappingRequestCompound>}
     * @memberof EzsignbulksendsignermappingCreateObjectV1Request
     */
    /*'a_objEzsignbulksendsignermapping': Array<EzsignbulksendsignermappingRequestCompound>;*/
    'a_objEzsignbulksendsignermapping': Array<EzsignbulksendsignermappingRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingCreateObjectV1Request
 */
export class DataObjectEzsignbulksendsignermappingCreateObjectV1Request {
   a_objEzsignbulksendsignermapping:Array<EzsignbulksendsignermappingRequestCompound> = []
}

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Request
 */
export class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Request {
   a_objEzsignbulksendsignermapping = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


