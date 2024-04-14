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
 * Payload for POST /1/object/usergroup
 * @export
 * @interface UsergroupCreateObjectV1ResponseMPayload
 */
export interface UsergroupCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof UsergroupCreateObjectV1ResponseMPayload
     */
    /*'a_pkiUsergroupID': Array<number>;*/
    'a_pkiUsergroupID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupCreateObjectV1ResponseMPayload
 */
export class DataObjectUsergroupCreateObjectV1ResponseMPayload {
   a_pkiUsergroupID:Array<number> = []
}

/**
 * @export 
 * A UsergroupCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupCreateObjectV1ResponseMPayload
 */
export class ValidationObjectUsergroupCreateObjectV1ResponseMPayload {
   a_pkiUsergroupID = {
      type: 'array',
      required: true
   }
} 


