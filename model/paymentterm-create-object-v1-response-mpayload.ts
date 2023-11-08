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
 * Payload for POST /1/object/paymentterm
 * @export
 * @interface PaymenttermCreateObjectV1ResponseMPayload
 */
export interface PaymenttermCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof PaymenttermCreateObjectV1ResponseMPayload
     */
    'a_pkiPaymenttermID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymenttermCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermCreateObjectV1ResponseMPayload
 */
export class DataObjectPaymenttermCreateObjectV1ResponseMPayload {
   a_pkiPaymenttermID:Array<number> = []
}

/**
 * @export 
 * A PaymenttermCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectPaymenttermCreateObjectV1ResponseMPayload
 */
export class ValidationObjectPaymenttermCreateObjectV1ResponseMPayload {
   a_pkiPaymenttermID = {
      type: 'array',
      required: true
   }
} 

