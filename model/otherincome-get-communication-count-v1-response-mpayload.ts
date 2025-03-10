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
 * Response for GET /1/object/otherincome/{pkiOtherincomeID}/getCommunicationCount
 * @export
 * @interface OtherincomeGetCommunicationCountV1ResponseMPayload
 */
export interface OtherincomeGetCommunicationCountV1ResponseMPayload {
    /**
     * The count of Communication.
     * @type {number}
     * @memberof OtherincomeGetCommunicationCountV1ResponseMPayload
     */
    /*'iCommunicationCount': number;*/
    'iCommunicationCount': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A OtherincomeGetCommunicationCountV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectOtherincomeGetCommunicationCountV1ResponseMPayload
 */
export class DataObjectOtherincomeGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount:number = 0
}

/**
 * @export 
 * A OtherincomeGetCommunicationCountV1ResponseMPayload Validation Object
 * @class ValidationObjectOtherincomeGetCommunicationCountV1ResponseMPayload
 */
export class ValidationObjectOtherincomeGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount = {
      type: 'integer',
      required: true
   }
} 


