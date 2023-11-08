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


// May contain unused imports in some cases
// @ts-ignore
import { CustomCommunicationListElementResponse } from './custom-communication-list-element-response';

/**
 * Response for GET /1/object/inscription/{pkiInscriptionID}/getCommunicationList
 * @export
 * @interface InscriptionGetCommunicationListV1ResponseMPayload
 */
export interface InscriptionGetCommunicationListV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomCommunicationListElementResponse>}
     * @memberof InscriptionGetCommunicationListV1ResponseMPayload
     */
    'a_objCommunication': Array<CustomCommunicationListElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A InscriptionGetCommunicationListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptionGetCommunicationListV1ResponseMPayload
 */
export class DataObjectInscriptionGetCommunicationListV1ResponseMPayload {
   a_objCommunication:Array<CustomCommunicationListElementResponse> = []
}

/**
 * @export 
 * A InscriptionGetCommunicationListV1ResponseMPayload Validation Object
 * @class ValidationObjectInscriptionGetCommunicationListV1ResponseMPayload
 */
export class ValidationObjectInscriptionGetCommunicationListV1ResponseMPayload {
   a_objCommunication = {
      type: 'array',
      required: true
   }
} 

