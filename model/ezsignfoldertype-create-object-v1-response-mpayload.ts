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



/**
 * Payload for POST /1/object/ezsignfoldertype
 * @export
 * @interface EzsignfoldertypeCreateObjectV1ResponseMPayload
 */
export interface EzsignfoldertypeCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignfoldertypeCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsignfoldertypeID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldertypeCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsignfoldertypeCreateObjectV1ResponseMPayload {
   a_pkiEzsignfoldertypeID:Array<number> = []
}

/**
 * @export 
 * A EzsignfoldertypeCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldertypeCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsignfoldertypeCreateObjectV1ResponseMPayload {
   a_pkiEzsignfoldertypeID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


