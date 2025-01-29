/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Response for GET /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getCommunicationCount
 * @export
 * @interface InscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload
 */
export interface InscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload {
    /**
     * The count of Communication.
     * @type {number}
     * @memberof InscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload
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
 * A InscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload
 */
export class DataObjectInscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount:number = 0
}

/**
 * @export 
 * A InscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload Validation Object
 * @class ValidationObjectInscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload
 */
export class ValidationObjectInscriptionnotauthenticatedGetCommunicationCountV1ResponseMPayload {
   iCommunicationCount = {
      type: 'integer',
      required: true
   }
} 


