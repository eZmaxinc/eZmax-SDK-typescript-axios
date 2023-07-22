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
 * Payload for POST /1/object/ezsignbulksend
 * @export
 * @interface EzsignbulksendCreateObjectV1ResponseMPayload
 */
export interface EzsignbulksendCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignbulksendCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsignbulksendID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsignbulksendCreateObjectV1ResponseMPayload {
   a_pkiEzsignbulksendID:Array<number> = []
}

/**
 * @export 
 * A EzsignbulksendCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksendCreateObjectV1ResponseMPayload {
   a_pkiEzsignbulksendID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


