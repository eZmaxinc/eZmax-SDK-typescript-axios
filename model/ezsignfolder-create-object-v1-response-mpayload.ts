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



/**
 * Payload for POST /1/object/ezsignfolder
 * @export
 * @interface EzsignfolderCreateObjectV1ResponseMPayload
 */
export interface EzsignfolderCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignfolderCreateObjectV1ResponseMPayload
     */
    /*'a_pkiEzsignfolderID': Array<number>;*/
    'a_pkiEzsignfolderID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsignfolderCreateObjectV1ResponseMPayload {
   a_pkiEzsignfolderID:Array<number> = []
}

/**
 * @export 
 * A EzsignfolderCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderCreateObjectV1ResponseMPayload {
   a_pkiEzsignfolderID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


