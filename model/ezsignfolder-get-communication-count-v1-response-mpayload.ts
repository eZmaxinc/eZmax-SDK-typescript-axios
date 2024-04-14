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
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationCount
 * @export
 * @interface EzsignfolderGetCommunicationCountV1ResponseMPayload
 */
export interface EzsignfolderGetCommunicationCountV1ResponseMPayload {
    /**
     * The count of Communication.
     * @type {number}
     * @memberof EzsignfolderGetCommunicationCountV1ResponseMPayload
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
 * A EzsignfolderGetCommunicationCountV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount:number = 0
}

/**
 * @export 
 * A EzsignfolderGetCommunicationCountV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount = {
      type: 'integer',
      required: true
   }
} 


