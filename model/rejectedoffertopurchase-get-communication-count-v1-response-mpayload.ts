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
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationCount
 * @export
 * @interface RejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload
 */
export interface RejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload {
    /**
     * The count of Communication.
     * @type {number}
     * @memberof RejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload
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
 * A RejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectRejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload
 */
export class DataObjectRejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount:number = 0
}

/**
 * @export 
 * A RejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload Validation Object
 * @class ValidationObjectRejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload
 */
export class ValidationObjectRejectedoffertopurchaseGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount = {
      type: 'integer',
      required: true
   }
} 


