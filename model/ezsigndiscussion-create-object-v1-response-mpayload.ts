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
 * Payload for POST /1/object/ezsigndiscussion
 * @export
 * @interface EzsigndiscussionCreateObjectV1ResponseMPayload
 */
export interface EzsigndiscussionCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigndiscussionCreateObjectV1ResponseMPayload
     */
    /*'a_pkiEzsigndiscussionID': Array<number>;*/
    'a_pkiEzsigndiscussionID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndiscussionCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsigndiscussionCreateObjectV1ResponseMPayload {
   a_pkiEzsigndiscussionID:Array<number> = []
}

/**
 * @export 
 * A EzsigndiscussionCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndiscussionCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigndiscussionCreateObjectV1ResponseMPayload {
   a_pkiEzsigndiscussionID = {
      type: 'array',
      required: true
   }
} 

