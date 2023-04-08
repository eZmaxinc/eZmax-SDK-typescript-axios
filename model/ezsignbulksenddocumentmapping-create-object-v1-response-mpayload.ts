/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for POST /1/object/ezsignbulksenddocumentmapping
 * @export
 * @interface EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload
 */
export interface EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsignbulksenddocumentmappingID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload {
   a_pkiEzsignbulksenddocumentmappingID:Array<number> = []
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload {
   a_pkiEzsignbulksenddocumentmappingID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


