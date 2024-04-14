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
 * Payload for POST /1/object/creditcardclient
 * @export
 * @interface CreditcardclientCreateObjectV1ResponseMPayload
 */
export interface CreditcardclientCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof CreditcardclientCreateObjectV1ResponseMPayload
     */
    /*'a_pkiCreditcardclientID': Array<number>;*/
    'a_pkiCreditcardclientID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardclientCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientCreateObjectV1ResponseMPayload
 */
export class DataObjectCreditcardclientCreateObjectV1ResponseMPayload {
   a_pkiCreditcardclientID:Array<number> = []
}

/**
 * @export 
 * A CreditcardclientCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectCreditcardclientCreateObjectV1ResponseMPayload
 */
export class ValidationObjectCreditcardclientCreateObjectV1ResponseMPayload {
   a_pkiCreditcardclientID = {
      type: 'array',
      required: true
   }
} 


