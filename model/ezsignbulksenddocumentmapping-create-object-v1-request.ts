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
import { EzsignbulksenddocumentmappingRequestCompound } from './ezsignbulksenddocumentmapping-request-compound';

/**
 * Request for POST /1/object/ezsignbulksenddocumentmapping
 * @export
 * @interface EzsignbulksenddocumentmappingCreateObjectV1Request
 */
export interface EzsignbulksenddocumentmappingCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignbulksenddocumentmappingRequestCompound>}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1Request
     */
    'a_objEzsignbulksenddocumentmapping': Array<EzsignbulksenddocumentmappingRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Request
 */
export class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Request {
   a_objEzsignbulksenddocumentmapping:Array<EzsignbulksenddocumentmappingRequestCompound> = []
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Request
 */
export class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Request {
   a_objEzsignbulksenddocumentmapping = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


